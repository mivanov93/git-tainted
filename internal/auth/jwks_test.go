package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	testIssuer = "https://idp.test/"
	testAud    = "git-tainted"
)

// staticKeySet is an in-memory keySet used to drive jwksAuth with no network
// (spec §2.8). It can simulate a never-ready / unreachable IdP and counts refresh
// calls so the on-demand rate-limit can be asserted.
type staticKeySet struct {
	set          jwk.Set
	readyFlag    bool
	lookupErr    error
	refreshCount atomic.Int64
	// onRefresh, if set, replaces the set returned by refresh (e.g. key rotation).
	onRefresh jwk.Set
}

func (s *staticKeySet) lookup(context.Context) (jwk.Set, error) {
	if s.lookupErr != nil {
		return nil, s.lookupErr
	}
	return s.set, nil
}

func (s *staticKeySet) refresh(context.Context) (jwk.Set, error) {
	s.refreshCount.Add(1)
	if s.onRefresh != nil {
		s.set = s.onRefresh
		s.readyFlag = true
		s.lookupErr = nil
		return s.onRefresh, nil
	}
	if s.lookupErr != nil {
		return nil, s.lookupErr
	}
	return s.set, nil
}

func (s *staticKeySet) ready(context.Context) bool { return s.readyFlag }

// rsaSigner is a generated RSA key plus its kid, used to mint and publish tokens.
type rsaSigner struct {
	priv jwk.Key // private jwk with kid+alg set
	pub  jwk.Key // public jwk with kid+alg set
	kid  string
	alg  jwa.SignatureAlgorithm
}

func newRSASigner(t *testing.T, kid string) rsaSigner {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return signerFromRaw(t, raw, kid, jwa.RS256())
}

func newECSigner(t *testing.T, kid string) rsaSigner {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return signerFromRaw(t, raw, kid, jwa.ES256())
}

func signerFromRaw(t *testing.T, raw any, kid string, alg jwa.SignatureAlgorithm) rsaSigner {
	t.Helper()
	priv, err := jwk.Import(raw)
	if err != nil {
		t.Fatalf("jwk.Import(priv): %v", err)
	}
	if err := priv.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := priv.Set(jwk.AlgorithmKey, alg); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	return rsaSigner{priv: priv, pub: pub, kid: kid, alg: alg}
}

// publicSet returns a JWKS containing the public keys of the given signers.
func publicSet(t *testing.T, signers ...rsaSigner) jwk.Set {
	t.Helper()
	set := jwk.NewSet()
	for _, s := range signers {
		if err := set.AddKey(s.pub); err != nil {
			t.Fatalf("AddKey: %v", err)
		}
	}
	return set
}

// claims customise a minted token.
type claims struct {
	iss    string
	aud    string
	sub    string
	exp    time.Time
	nbf    time.Time
	iat    time.Time
}

// signToken mints a signed compact JWT with the signer's key and the given claims.
func signToken(t *testing.T, s rsaSigner, c claims) string {
	t.Helper()
	now := time.Now()
	if c.iss == "" {
		c.iss = testIssuer
	}
	if c.aud == "" {
		c.aud = testAud
	}
	if c.sub == "" {
		c.sub = "user-123"
	}
	if c.exp.IsZero() {
		c.exp = now.Add(5 * time.Minute)
	}
	if c.iat.IsZero() {
		c.iat = now
	}
	if c.nbf.IsZero() {
		c.nbf = now.Add(-1 * time.Minute)
	}
	tok, err := jwt.NewBuilder().
		Issuer(c.iss).
		Audience([]string{c.aud}).
		Subject(c.sub).
		Expiration(c.exp).
		IssuedAt(c.iat).
		NotBefore(c.nbf).
		Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(s.alg, s.priv))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

// req builds a GET request carrying the given bearer token (empty = no header).
func bearerReq(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/remotes", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func newTestJWKS(ks keySet) *jwksAuth {
	return newJWKSAuthWithKeySet(ks, testIssuer, testAud, []jwa.SignatureAlgorithm{jwa.RS256(), jwa.ES256()})
}

func TestJWKS_ValidRS256(t *testing.T) {
	s := newRSASigner(t, "key-1")
	ks := &staticKeySet{set: publicSet(t, s), readyFlag: true}
	a := newTestJWKS(ks)

	principal, err := a.Authenticate(bearerReq(signToken(t, s, claims{sub: "alice"})))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if principal != "jwt:alice" {
		t.Errorf("principal = %q, want jwt:alice", principal)
	}
}

func TestJWKS_ValidES256(t *testing.T) {
	s := newECSigner(t, "ec-1")
	ks := &staticKeySet{set: publicSet(t, s), readyFlag: true}
	a := newTestJWKS(ks)

	if _, err := a.Authenticate(bearerReq(signToken(t, s, claims{}))); err != nil {
		t.Fatalf("valid ES256 token rejected: %v", err)
	}
}

func TestJWKS_Rejections(t *testing.T) {
	signer := newRSASigner(t, "key-1")
	// A second signer whose public key is NOT published → unknown signer.
	unpublished := newRSASigner(t, "key-unpublished")
	// HS256 symmetric signer, published with the same kid → must still be rejected.
	hsKey, err := jwk.Import([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("import hs key: %v", err)
	}
	_ = hsKey.Set(jwk.KeyIDKey, "key-1")
	_ = hsKey.Set(jwk.AlgorithmKey, jwa.HS256())

	base := func() *staticKeySet {
		return &staticKeySet{set: publicSet(t, signer), readyFlag: true}
	}

	tests := []struct {
		name    string
		token   string
		wantErr error
	}{
		{
			name:    "missing credential",
			token:   "",
			wantErr: errMissingCredential,
		},
		{
			name:    "garbage token",
			token:   "not-a-jwt",
			wantErr: errBadCredential,
		},
		{
			name:    "expired",
			token:   signToken(t, signer, claims{exp: time.Now().Add(-10 * time.Minute), iat: time.Now().Add(-20 * time.Minute), nbf: time.Now().Add(-20 * time.Minute)}),
			wantErr: errBadCredential,
		},
		{
			name:    "not yet valid (nbf in future beyond skew)",
			token:   signToken(t, signer, claims{nbf: time.Now().Add(10 * time.Minute)}),
			wantErr: errBadCredential,
		},
		{
			name:    "wrong issuer",
			token:   signToken(t, signer, claims{iss: "https://evil.test/"}),
			wantErr: errBadCredential,
		},
		{
			name:    "wrong audience",
			token:   signToken(t, signer, claims{aud: "some-other-service"}),
			wantErr: errBadCredential,
		},
		{
			name:    "unknown signer (kid not in JWKS)",
			token:   signToken(t, unpublished, claims{}),
			wantErr: errBadCredential,
		},
		{
			name:    "HS256 token rejected under jwks",
			token:   signHS256(t, "key-1"),
			wantErr: errBadCredential,
		},
		{
			name:    "alg:none token rejected",
			token:   noneToken(t),
			wantErr: errBadCredential,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ks := base()
			a := newTestJWKS(ks)
			_, err := a.Authenticate(bearerReq(tc.token))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestJWKS_AlgNotAllowed verifies that a correctly-signed token whose algorithm
// is outside the allowlist is rejected (e.g. an allowlist of only ES256 rejects a
// valid RS256 token).
func TestJWKS_AlgNotAllowed(t *testing.T) {
	s := newRSASigner(t, "key-1")
	ks := &staticKeySet{set: publicSet(t, s), readyFlag: true}
	// Allowlist ES256 only — the RS256 token must be refused at the alg gate.
	a := newJWKSAuthWithKeySet(ks, testIssuer, testAud, []jwa.SignatureAlgorithm{jwa.ES256()})
	_, err := a.Authenticate(bearerReq(signToken(t, s, claims{})))
	if !errors.Is(err, errBadCredential) {
		t.Fatalf("RS256-not-in-allowlist: err = %v, want errBadCredential", err)
	}
}

// TestJWKS_IdPUnavailable verifies fail-closed behavior: a never-ready cache (IdP
// unreachable) yields errIdPUnavailable, not a 5xx and not a pass.
func TestJWKS_IdPUnavailable(t *testing.T) {
	s := newRSASigner(t, "key-1")
	ks := &staticKeySet{lookupErr: errors.New("dial tcp: connection refused"), readyFlag: false}
	a := newTestJWKS(ks)
	_, err := a.Authenticate(bearerReq(signToken(t, s, claims{})))
	if !errors.Is(err, errIdPUnavailable) {
		t.Fatalf("unreachable IdP: err = %v, want errIdPUnavailable", err)
	}
}

// TestJWKS_UnknownKidTriggersRateLimitedRefresh verifies that an unknown kid
// triggers at most one on-demand refresh within the min interval, and that a
// successful rotation refresh then authenticates.
func TestJWKS_UnknownKidTriggersRateLimitedRefresh(t *testing.T) {
	rotated := newRSASigner(t, "key-2")
	// Start with an empty published set but a cache that, on refresh, returns the
	// rotated key's JWKS (simulating key rotation observed via on-demand fetch).
	ks := &staticKeySet{set: jwk.NewSet(), readyFlag: true, onRefresh: publicSet(t, rotated)}
	a := newTestJWKS(ks)

	// First call: kid key-2 unknown → refresh → now present → authenticates.
	if _, err := a.Authenticate(bearerReq(signToken(t, rotated, claims{}))); err != nil {
		t.Fatalf("post-rotation token rejected: %v", err)
	}
	if got := ks.refreshCount.Load(); got != 1 {
		t.Fatalf("refreshCount = %d, want 1", got)
	}

	// Immediately present a different unknown kid: the on-demand refresh must be
	// rate-limited (no second refresh within the min interval).
	other := newRSASigner(t, "key-3")
	_, _ = a.Authenticate(bearerReq(signToken(t, other, claims{})))
	if got := ks.refreshCount.Load(); got != 1 {
		t.Fatalf("refreshCount after rapid second unknown kid = %d, want 1 (rate-limited)", got)
	}
}

// TestParseAlgs covers the allowlist parser including the always-rejected algs.
func TestParseAlgs(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantLen int
		wantErr bool
	}{
		{"default when empty", "", 2, false},
		{"single RS256", "RS256", 1, false},
		{"two with spaces", "RS256, ES256", 2, false},
		{"dedup", "RS256,RS256", 1, false},
		{"reject none", "RS256,none", 0, true},
		{"reject HS256", "HS256", 0, true},
		{"reject unknown", "RS999", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAlgs(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseAlgs(%q) = nil err, want error", tc.spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAlgs(%q): %v", tc.spec, err)
			}
			if len(got) != tc.wantLen {
				t.Fatalf("parseAlgs(%q) len = %d, want %d", tc.spec, len(got), tc.wantLen)
			}
		})
	}
}
