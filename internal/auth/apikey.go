package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

// apiKeyAuth authenticates by a shared secret presented as a bearer token or an
// X-API-Key header. Keys are never held in cleartext: each is reduced to its
// SHA-256 digest at construction (raw GT_API_KEYS values are hashed and dropped;
// GT_API_KEYS_SHA256 values arrive already hashed). Verification hashes the
// presented key and constant-time-compares the digest against every configured
// digest, so neither validity nor which key matched leaks via timing.
type apiKeyAuth struct {
	// digests holds the accepted SHA-256 key digests (32 bytes each).
	digests [][sha256.Size]byte
}

// newAPIKeyAuth builds an apiKeyAuth from raw keys and/or pre-hashed hex digests.
//   - rawKeys: cleartext keys, each SHA-256-hashed here and the cleartext dropped.
//   - hexDigests: lowercase-hex SHA-256 digests (raw key never enters the server).
//
// At least one usable key is required; an empty/whitespace raw key is ignored,
// and a malformed hex digest is a fatal configuration error.
func newAPIKeyAuth(rawKeys, hexDigests []string) (*apiKeyAuth, error) {
	a := &apiKeyAuth{}
	seen := make(map[[sha256.Size]byte]struct{})
	add := func(d [sha256.Size]byte) {
		if _, dup := seen[d]; dup {
			return
		}
		seen[d] = struct{}{}
		a.digests = append(a.digests, d)
	}
	for _, k := range rawKeys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		add(sha256.Sum256([]byte(k)))
	}
	for _, h := range hexDigests {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != sha256.Size {
			return nil, errors.New("auth: GT_API_KEYS_SHA256 entry is not a 64-char lowercase-hex SHA-256 digest: " + h)
		}
		var d [sha256.Size]byte
		copy(d[:], raw)
		add(d)
	}
	if len(a.digests) == 0 {
		return nil, errors.New("auth: apikey mode requires at least one key (GT_API_KEYS or GT_API_KEYS_SHA256)")
	}
	return a, nil
}

// Authenticate extracts the presented key from Authorization: Bearer or the
// X-API-Key header, hashes it, and constant-time-matches it against the
// configured digest set. The whole set is always scanned (no early return) so
// the comparison cost does not depend on which — or whether a — key matched.
func (a *apiKeyAuth) Authenticate(r *http.Request) (string, error) {
	key := presentedAPIKey(r)
	if key == "" {
		return "", errMissingCredential
	}
	got := sha256.Sum256([]byte(key))
	matched := false
	for i := range a.digests {
		if subtle.ConstantTimeCompare(got[:], a.digests[i][:]) == 1 {
			matched = true
		}
	}
	if !matched {
		return "", errBadCredential
	}
	// Principal is a stable, non-secret handle for the key: its digest prefix.
	return "apikey:" + hex.EncodeToString(got[:4]), nil
}

func (a *apiKeyAuth) Challenge() string { return "Bearer" }

// presentedAPIKey returns the API key from the request, preferring the
// Authorization: Bearer header and falling back to X-API-Key. Returns "" if
// neither is present or the Authorization scheme is not Bearer.
func presentedAPIKey(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if rest, ok := bearerToken(h); ok {
			return rest
		}
		// An Authorization header with a non-Bearer scheme is not an API key.
		return ""
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

// bearerToken splits an "Authorization: Bearer <token>" value. The scheme match
// is case-insensitive per RFC 7235; the token is returned verbatim (trimmed).
func bearerToken(header string) (string, bool) {
	const prefix = "bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(header[len(prefix):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

var _ Authenticator = (*apiKeyAuth)(nil)
