package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Default skew leeway applied to exp/nbf/iat to tolerate small clock differences
// between the IdP and this server (spec §2.3).
const jwtSkew = 60 * time.Second

// Defaults for the background JWKS refresh cadence. The cache refreshes on its
// own TTL; an unknown-kid arrival can trigger one extra on-demand fetch, but no
// more often than onDemandMinInterval to prevent a fetch-amplification DoS.
const (
	jwksMinRefreshInterval = 15 * time.Minute
	onDemandMinInterval    = 1 * time.Minute
)

// keySet is the minimal surface of *jwk.Cache that jwksAuth needs; abstracting it
// lets unit tests inject an in-memory JWKS (no network, spec §2.8).
type keySet interface {
	// lookup returns the currently-cached JWK set.
	lookup(ctx context.Context) (jwk.Set, error)
	// refresh forces a re-fetch and returns the fresh set.
	refresh(ctx context.Context) (jwk.Set, error)
	// ready reports whether at least one successful fetch has populated the cache.
	ready(ctx context.Context) bool
}

// jwksAuth verifies bearer JWTs against a JWKS fetched (and background-refreshed)
// from GT_JWKS_URL. It enforces an algorithm allowlist (default RS256,ES256;
// `none` and all HS* are always rejected), verifies the signature by `kid`, and
// validates exp/nbf/iat (±skew), iss and aud. If the JWKS is unreachable it fails
// closed (denied, not 5xx) so an IdP blip never opens the control plane and an
// attacker cannot distinguish "down" from "denied".
type jwksAuth struct {
	keys     keySet
	issuer   string
	audience string
	algs     []jwa.SignatureAlgorithm // allowlist (asymmetric only)
	algNames map[string]bool          // fast membership by canonical name

	mu            sync.Mutex
	lastOnDemand  time.Time
	onDemandEvery time.Duration
}

// cacheKeySet adapts *jwk.Cache (the real background-refreshing cache) to keySet.
type cacheKeySet struct {
	cache *jwk.Cache
	url   string
}

func (c *cacheKeySet) lookup(ctx context.Context) (jwk.Set, error) {
	return c.cache.Lookup(ctx, c.url)
}

func (c *cacheKeySet) refresh(ctx context.Context) (jwk.Set, error) {
	return c.cache.Refresh(ctx, c.url)
}

func (c *cacheKeySet) ready(ctx context.Context) bool {
	return c.cache.Ready(ctx, c.url)
}

// newJWKSAuth builds a jwksAuth bound to a background-refreshing JWKS cache. The
// cache's refresh goroutine is tied to ctx (cancel it to stop refreshing). issuer
// and audience are required (validated by the caller / FromConfig); algNames is
// the parsed, validated allowlist.
func newJWKSAuth(ctx context.Context, url, issuer, audience string, algs []jwa.SignatureAlgorithm) (*jwksAuth, error) {
	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, err
	}
	// WithWaitReady(false): do NOT block startup on the IdP — Register returns
	// immediately and the JWKS is fetched by the background refresh goroutine.
	// Until the first successful fetch, Lookup fails and verification fails closed
	// (errIdPUnavailable), which is the correct posture (spec §2.3/§2.7). With the
	// default (WaitReady=true) a down or slow IdP would block the server from
	// starting — and the unit test would hang fetching an unreachable URL.
	if err := cache.Register(ctx, url,
		jwk.WithMinInterval(jwksMinRefreshInterval),
		jwk.WithWaitReady(false),
	); err != nil {
		return nil, err
	}
	return newJWKSAuthWithKeySet(&cacheKeySet{cache: cache, url: url}, issuer, audience, algs), nil
}

// newJWKSAuthWithKeySet builds a jwksAuth over an arbitrary keySet (the test seam).
func newJWKSAuthWithKeySet(ks keySet, issuer, audience string, algs []jwa.SignatureAlgorithm) *jwksAuth {
	names := make(map[string]bool, len(algs))
	for _, a := range algs {
		names[a.String()] = true
	}
	return &jwksAuth{
		keys:          ks,
		issuer:        issuer,
		audience:      audience,
		algs:          algs,
		algNames:      names,
		onDemandEvery: onDemandMinInterval,
	}
}

// Authenticate verifies the bearer JWT. The flow, in order:
//  1. extract the bearer token (missing → 401);
//  2. parse the JWS header and reject any alg outside the allowlist (this is where
//     `alg:none` and HS* die, before any key is consulted);
//  3. obtain the JWKS, doing one rate-limited on-demand refresh if the token's kid
//     is not yet cached;
//  4. restrict the set to allowlisted-alg keys and verify signature + claims.
//
// JWKS-unreachable at step 3 → errIdPUnavailable (fail closed). The principal on
// success is "jwt:<sub>" (or "jwt:" when the token carries no subject).
func (a *jwksAuth) Authenticate(r *http.Request) (string, error) {
	raw := bearerOnly(r)
	if raw == "" {
		return "", errMissingCredential
	}
	tokenBytes := []byte(raw)

	kid, err := a.assertAllowedAlg(tokenBytes)
	if err != nil {
		return "", err
	}

	ctx := r.Context()
	set, err := a.resolveSet(ctx, kid)
	if err != nil {
		return "", err
	}

	verifyKeys, err := a.allowlistedKeys(set)
	if err != nil {
		return "", err
	}

	tok, err := jwt.Parse(tokenBytes,
		jwt.WithKeySet(verifyKeys),
		jwt.WithValidate(true),
		jwt.WithContext(ctx),
		jwt.WithIssuer(a.issuer),
		jwt.WithAudience(a.audience),
		jwt.WithAcceptableSkew(jwtSkew),
	)
	if err != nil {
		return "", errBadCredential
	}
	sub, _ := tok.Subject()
	return "jwt:" + sub, nil
}

func (a *jwksAuth) Challenge() string { return "Bearer" }

// assertAllowedAlg parses the compact JWS, requires exactly one signature, and
// rejects any algorithm not in the allowlist (covering `none` and HS*). It returns
// the token's `kid` (possibly empty) so the caller can decide on an on-demand
// JWKS refresh.
func (a *jwksAuth) assertAllowedAlg(token []byte) (kid string, err error) {
	msg, perr := jws.Parse(token)
	if perr != nil {
		return "", errBadCredential
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		// Multi-signature / unsigned compact tokens are not accepted here.
		return "", errBadCredential
	}
	hdr := sigs[0].ProtectedHeaders()
	alg, ok := hdr.Algorithm()
	if !ok {
		return "", errBadCredential
	}
	// Symmetric (HS*) and the empty "none" algorithm are categorically rejected,
	// independent of the allowlist, as a defense-in-depth belt to the alg check.
	if alg.IsSymmetric() || alg.String() == "none" || alg.String() == "" {
		return "", errBadCredential
	}
	if !a.algNames[alg.String()] {
		return "", errBadCredential
	}
	if kidHdr, ok := hdr.KeyID(); ok {
		kid = kidHdr
	}
	return kid, nil
}

// resolveSet returns the cached JWKS, performing one rate-limited on-demand
// refresh when the requested kid is absent (key rotation). If the cache has never
// successfully fetched, it returns errIdPUnavailable (fail closed).
func (a *jwksAuth) resolveSet(ctx context.Context, kid string) (jwk.Set, error) {
	set, err := a.keys.lookup(ctx)
	if err == nil && (kid == "" || hasKey(set, kid)) {
		return set, nil
	}
	// kid missing (or first lookup failed): consider one rate-limited refresh.
	if a.allowOnDemand() {
		if fresh, rerr := a.keys.refresh(ctx); rerr == nil {
			return fresh, nil
		}
		// Refresh failed: fall through to whatever we have / fail closed below.
	}
	if err == nil && set != nil {
		// We have a cached set but not this kid; let verification fail as a bad
		// credential (unknown signer) rather than masquerading as IdP-down.
		return set, nil
	}
	if !a.keys.ready(ctx) {
		return nil, errIdPUnavailable
	}
	return nil, errIdPUnavailable
}

// allowOnDemand reports whether an on-demand refresh is permitted now, enforcing
// a minimum interval so a flood of unknown-kid tokens cannot amplify into a flood
// of JWKS fetches (DoS guard, spec §2.4/§7).
func (a *jwksAuth) allowOnDemand() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if !a.lastOnDemand.IsZero() && now.Sub(a.lastOnDemand) < a.onDemandEvery {
		return false
	}
	a.lastOnDemand = now
	return true
}

// allowlistedKeys returns a new jwk.Set containing only keys whose declared `alg`
// is in the allowlist. This guarantees a JWKS that (mis)includes a symmetric or
// otherwise-disallowed key can never be used to verify a control token. A key
// with no `alg` is dropped (WithKeySet requires a concrete alg anyway). An empty
// result is treated as IdP-unusable (fail closed).
func (a *jwksAuth) allowlistedKeys(set jwk.Set) (jwk.Set, error) {
	out := jwk.NewSet()
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		ka, ok := key.Algorithm()
		if !ok {
			continue
		}
		if !a.algNames[ka.String()] {
			continue
		}
		if err := out.AddKey(key); err != nil {
			return nil, errBadCredential
		}
	}
	if out.Len() == 0 {
		return nil, errIdPUnavailable
	}
	return out, nil
}

// hasKey reports whether the set contains a key with the given kid.
func hasKey(set jwk.Set, kid string) bool {
	if set == nil || kid == "" {
		return false
	}
	_, ok := set.LookupKeyID(kid)
	return ok
}

// bearerOnly returns the token from an Authorization: Bearer header only (JWTs are
// not sent via X-API-Key). Returns "" when absent or the scheme is not Bearer.
func bearerOnly(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	tok, ok := bearerToken(h)
	if !ok {
		return ""
	}
	return strings.TrimSpace(tok)
}

// parseAlgs parses a comma-separated algorithm allowlist into validated asymmetric
// SignatureAlgorithms. `none` and HS* are rejected as configuration errors (they
// can never be allowlisted). Unknown names are configuration errors. An empty/blank
// spec yields the default RS256,ES256.
func parseAlgs(spec string) ([]jwa.SignatureAlgorithm, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return []jwa.SignatureAlgorithm{jwa.RS256(), jwa.ES256()}, nil
	}
	var out []jwa.SignatureAlgorithm
	seen := make(map[string]bool)
	for _, raw := range strings.Split(spec, ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if strings.EqualFold(name, "none") {
			return nil, errors.New("auth: GT_JWT_ALGS may not include 'none'")
		}
		alg, ok := jwa.LookupSignatureAlgorithm(name)
		if !ok {
			return nil, errors.New("auth: GT_JWT_ALGS contains an unknown algorithm: " + name)
		}
		if alg.IsSymmetric() {
			return nil, errors.New("auth: GT_JWT_ALGS may not include symmetric algorithm " + name + " (HS* are forbidden)")
		}
		if !seen[alg.String()] {
			seen[alg.String()] = true
			out = append(out, alg)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("auth: GT_JWT_ALGS resolved to an empty allowlist")
	}
	return out, nil
}

var _ Authenticator = (*jwksAuth)(nil)
