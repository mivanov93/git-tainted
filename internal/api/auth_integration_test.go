package api_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"golang.org/x/crypto/bcrypt"

	"github.com/mivanov93/git-tainted/internal/api"
	"github.com/mivanov93/git-tainted/internal/auth"
	"github.com/mivanov93/git-tainted/internal/config"
	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/testutil"
)

// remotePath returns the canonical /v1/remotes/{id} path.
func remotePath(id model.RemoteID) string { return "/v1/remotes/" + strconv.FormatInt(int64(id), 10) }

// itoa formats an int64 as decimal.
func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// stringsNewReader wraps strings.NewReader so request bodies read once cleanly.
func stringsNewReader(s string) io.Reader { return strings.NewReader(s) }

// bcryptForTest hashes pw at the default cost for basic-auth fixtures.
func bcryptForTest(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

// authFixedClock is a trivial model.Clock for these tests.
type authFixedClock struct{ ns int64 }

func (c authFixedClock) NowNS() int64 { return c.ns }

// seededIDs holds the ids the matrix needs to exercise real 2xx responses.
type seededIDs struct {
	remoteID     model.RemoteID // for update/delete/sync/get
	syncRemoteID model.RemoteID // a separate remote so triggerSync's seed isn't deleted
	taintEventID int64          // for ackTaintEvent → real 204
	taintRemote  model.RemoteID // owner of the taint event
}

// seedFixtures inserts the remotes, a ref projection, and a taint event used by
// the control-op matrix.
func seedFixtures(t *testing.T, s model.Store) seededIDs {
	t.Helper()
	ctx := context.Background()
	ids := seededIDs{
		remoteID:     testutil.SeedRemote(t, s, "https://example.com/a.git"),
		syncRemoteID: testutil.SeedRemote(t, s, "https://example.com/b.git"),
		taintRemote:  testutil.SeedRemote(t, s, "https://example.com/c.git"),
	}
	// Create a ref projection + taint event on taintRemote so AckTaintEvent can
	// return a genuine 204 when authorized.
	err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
		ref := &model.Ref{
			RemoteID:      ids.taintRemote,
			TagName:       "v1.0.0",
			FirstSeenNS:   1,
			LastSeenNS:    1,
			LastChangedNS: 1,
			Tainted:       true,
		}
		if err := tx.UpsertRefProjection(ctx, ref); err != nil {
			return err
		}
		_, err := tx.AppendTaintEvent(ctx, &model.TaintEvent{
			RemoteID:     ids.taintRemote,
			RefID:        ref.ID,
			Reason:       model.TaintTagDeletedRecreated,
			DetectedAtNS: 2,
			Detail:       "seed",
		})
		return err
	})
	if err != nil {
		t.Fatalf("seed taint event: %v", err)
	}
	// Read the event id back.
	events, _, err := s.ListTaintEvents(ctx, ids.taintRemote, 10, 0)
	if err != nil || len(events) == 0 {
		t.Fatalf("list seeded taint events: err=%v n=%d", err, len(events))
	}
	ids.taintEventID = events[0].ID
	return ids
}

// authedRequest describes one control or open operation plus how to address it.
type opCase struct {
	name    string
	method  string
	path    func(ids seededIDs) string
	body    string
	control bool // true = gated; false = open (must be reachable without creds)
}

func opMatrix() []opCase {
	return []opCase{
		// ---- control (gated) ----
		// createRemote's body is assigned per-call in doReq (unique URL per attempt).
		{"createRemote", http.MethodPost, func(seededIDs) string { return "/v1/remotes" }, ``, true},
		{"updateRemote", http.MethodPatch, func(i seededIDs) string { return remotePath(i.remoteID) },
			`{"sync_interval_ns":600000000000}`, true},
		{"triggerSync", http.MethodPost, func(i seededIDs) string { return remotePath(i.syncRemoteID) + "/sync" }, ``, true},
		{"deleteRemote", http.MethodDelete, func(i seededIDs) string { return remotePath(i.remoteID) }, ``, true},
		{"ackTaintEvent", http.MethodPost, func(i seededIDs) string {
			return remotePath(i.taintRemote) + "/taint-events/" + itoa(i.taintEventID) + "/ack"
		}, `{"ack_note":"ok"}`, true},

		// ---- open (never gated) ----
		{"verify", http.MethodGet, func(i seededIDs) string {
			return "/v1/verify?remote=" + itoa(int64(i.remoteID)) + "&tag=v1.0.0"
		}, ``, false},
		{"listRemotes", http.MethodGet, func(seededIDs) string { return "/v1/remotes" }, ``, false},
		{"getRemote", http.MethodGet, func(i seededIDs) string { return remotePath(i.remoteID) }, ``, false},
		{"listSyncs", http.MethodGet, func(i seededIDs) string { return remotePath(i.remoteID) + "/syncs" }, ``, false},
		{"listTags", http.MethodGet, func(i seededIDs) string { return remotePath(i.remoteID) + "/tags" }, ``, false},
		{"listTaintEvents", http.MethodGet, func(i seededIDs) string { return remotePath(i.taintRemote) + "/taint-events" }, ``, false},
		{"healthz", http.MethodGet, func(seededIDs) string { return "/healthz" }, ``, false},
	}
}

// authMode bundles an Authenticator and the matching valid credential applier.
type authMode struct {
	name      string
	build     func(t *testing.T) (auth.Authenticator, func(*http.Request), func())
	challenge string
}

// TestServerAuthMatrix is the §2.8 server-level guarantee: across all four modes,
// EVERY control op 401s without creds and 2xx with, and EVERY open op is reachable
// with no creds.
func TestServerAuthMatrix(t *testing.T) {
	modes := []authMode{
		{
			name: "none",
			build: func(*testing.T) (auth.Authenticator, func(*http.Request), func()) {
				return auth.None(), func(*http.Request) {}, func() {}
			},
		},
		{
			name: "apikey",
			build: func(t *testing.T) (auth.Authenticator, func(*http.Request), func()) {
				a, err := auth.FromConfig(context.Background(),
					&config.Config{AuthMode: config.AuthModeAPIKey, APIKeys: "test-key-123"})
				if err != nil {
					t.Fatalf("apikey FromConfig: %v", err)
				}
				return a, func(r *http.Request) { r.Header.Set("Authorization", "Bearer test-key-123") }, func() {}
			},
			challenge: "Bearer",
		},
		{
			name: "basic",
			build: func(t *testing.T) (auth.Authenticator, func(*http.Request), func()) {
				hash := bcryptForTest(t, "s3cret")
				a, err := auth.FromConfig(context.Background(),
					&config.Config{AuthMode: config.AuthModeBasic, BasicAuth: "operator:" + hash})
				if err != nil {
					t.Fatalf("basic FromConfig: %v", err)
				}
				return a, func(r *http.Request) { r.SetBasicAuth("operator", "s3cret") }, func() {}
			},
			challenge: `Basic realm="git-tainted"`,
		},
		{
			name: "jwks",
			build: func(t *testing.T) (auth.Authenticator, func(*http.Request), func()) {
				signer, jwksSrv := startLocalJWKS(t)
				cfg := &config.Config{
					AuthMode:    config.AuthModeJWKS,
					JWKSURL:     jwksSrv.URL,
					JWTIssuer:   jwksTestIssuer,
					JWTAudience: jwksTestAud,
					JWTAlgs:     "RS256,ES256",
				}
				a, err := auth.FromConfig(context.Background(), cfg)
				if err != nil {
					jwksSrv.Close()
					t.Fatalf("jwks FromConfig: %v", err)
				}
				apply := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+signer.mint(t)) }
				return a, apply, jwksSrv.Close
			},
			challenge: "Bearer",
		},
	}

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			s := testutil.NewTestStore(t)
			ids := seedFixtures(t, s)
			authn, applyCreds, cleanup := m.build(t)
			defer cleanup()

			srv := httptest.NewServer(api.NewServer(s, authFixedClock{ns: 1_718_000_000_000_000_000}, nil, authn, nil))
			defer srv.Close()

			for _, op := range opMatrix() {
				op := op
				t.Run(op.name, func(t *testing.T) {
					if op.control {
						// 1) No creds → 401 + challenge (except none mode, which allows).
						resp := doReq(t, srv.URL, op, ids, "create-noauth", nil)
						if m.name == "none" {
							if resp.StatusCode == http.StatusUnauthorized {
								t.Fatalf("none mode: %s returned 401", op.name)
							}
						} else {
							if resp.StatusCode != http.StatusUnauthorized {
								t.Fatalf("%s without creds: status=%d, want 401", op.name, resp.StatusCode)
							}
							if got := resp.Header.Get("WWW-Authenticate"); got != m.challenge {
								t.Errorf("%s 401 WWW-Authenticate=%q, want %q", op.name, got, m.challenge)
							}
						}
						_ = resp.Body.Close()

						// 2) With creds → 2xx (auth gate passed AND handler succeeded).
						resp2 := doReq(t, srv.URL, op, ids, "create-auth", applyCreds)
						if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
							b, _ := io.ReadAll(resp2.Body)
							t.Fatalf("%s with creds: status=%d (want 2xx); body=%s", op.name, resp2.StatusCode, b)
						}
						_ = resp2.Body.Close()
					} else {
						// Open op: reachable with NO creds (never 401).
						resp := doReq(t, srv.URL, op, ids, "", nil)
						if resp.StatusCode == http.StatusUnauthorized {
							t.Fatalf("open op %s returned 401 without creds", op.name)
						}
						_ = resp.Body.Close()
					}
				})
			}
		})
	}
}

// doReq issues the operation's request. unique disambiguates createRemote bodies
// (so the "noauth" and "auth" createRemote calls use distinct URLs and the second
// is a real 201, not a 409).
func doReq(t *testing.T, base string, op opCase, ids seededIDs, unique string, applyCreds func(*http.Request)) *http.Response {
	t.Helper()
	body := op.body
	if op.name == "createRemote" {
		body = `{"url":"https://example.com/` + unique + `.git","transport":"https"}`
	}
	var rdr io.Reader
	if body != "" {
		rdr = stringsNewReader(body)
	}
	req, err := http.NewRequest(op.method, base+op.path(ids), rdr)
	if err != nil {
		t.Fatalf("new request %s: %v", op.name, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if applyCreds != nil {
		applyCreds(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s: %v", op.name, err)
	}
	return resp
}

// ---- jwks local fixture (loopback httptest server, no external network) ------

const (
	jwksTestIssuer = "https://idp.local/"
	jwksTestAud    = "git-tainted"
)

type localSigner struct {
	priv jwk.Key
	alg  jwa.SignatureAlgorithm
}

func (l localSigner) mint(t *testing.T) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer(jwksTestIssuer).
		Audience([]string{jwksTestAud}).
		Subject("ci-operator").
		Expiration(time.Now().Add(5 * time.Minute)).
		IssuedAt(time.Now()).
		Build()
	if err != nil {
		t.Fatalf("build jwt: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(l.alg, l.priv))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return string(signed)
}

// startLocalJWKS generates an RSA key and serves its public JWKS from a loopback
// httptest.Server, returning the signer and the server (caller closes it).
func startLocalJWKS(t *testing.T) (localSigner, *httptest.Server) {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	priv, err := jwk.Import[jwk.Key](raw)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	_ = priv.Set(jwk.KeyIDKey, "local-1")
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256())
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	return localSigner{priv: priv, alg: jwa.RS256()}, srv
}
