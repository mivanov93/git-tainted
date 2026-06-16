package auth

import (
	"errors"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// dummyBcryptHash is a valid bcrypt hash (of the string "dummy", cost 10) used to
// flatten timing when an unknown username is presented: we run a real
// CompareHashAndPassword against it so the response time of "unknown user" is
// indistinguishable from "known user, wrong password". It is never a valid
// credential (no username maps to it).
const dummyBcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// basicAuth authenticates via HTTP Basic, verifying the password against a
// per-user bcrypt hash (htpasswd-style). Configured as comma-separated
// "user:bcrypt-hash" entries; raw passwords never enter the server environment.
// Unknown user and wrong password yield the same generic 401 (no user-enumeration
// oracle), and an unknown user still pays a bcrypt comparison to flatten timing.
type basicAuth struct {
	users map[string]string // username -> bcrypt hash
}

// newBasicAuth parses GT_BASIC_AUTH entries ("user:bcrypt-hash", comma-separated).
// At least one entry is required; a malformed entry or a hash bcrypt rejects as a
// non-hash is a fatal configuration error (caught here, not per-request).
func newBasicAuth(entries []string) (*basicAuth, error) {
	a := &basicAuth{users: make(map[string]string)}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		// Split on the FIRST colon only: bcrypt hashes contain no ':' but a
		// username conceivably could not (htpasswd forbids it); first-colon split
		// is the htpasswd convention.
		user, hash, ok := strings.Cut(e, ":")
		if !ok || user == "" || hash == "" {
			return nil, errors.New("auth: GT_BASIC_AUTH entry must be user:bcrypt-hash")
		}
		// Validate the hash is a well-formed bcrypt hash up front so misconfig is
		// fatal at startup, not a silent always-deny at request time.
		if _, err := bcrypt.Cost([]byte(hash)); err != nil {
			return nil, errors.New("auth: GT_BASIC_AUTH hash for user " + user + " is not a valid bcrypt hash: " + err.Error())
		}
		a.users[user] = hash
	}
	if len(a.users) == 0 {
		return nil, errors.New("auth: basic mode requires at least one user (GT_BASIC_AUTH)")
	}
	return a, nil
}

// Authenticate reads HTTP Basic credentials and verifies the password against the
// user's bcrypt hash. On an unknown user it compares against a dummy hash so the
// timing matches a wrong-password attempt; either way the failure is the same
// generic error mapped to a 401 by the middleware.
func (a *basicAuth) Authenticate(r *http.Request) (string, error) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return "", errMissingCredential
	}
	hash, known := a.users[user]
	if !known {
		// Flatten timing: run a real bcrypt comparison that always fails, then
		// return the same generic error as a wrong password. Avoids a
		// user-enumeration timing oracle.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(pass))
		return "", errBadCredential
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)); err != nil {
		return "", errBadCredential
	}
	return "basic:" + user, nil
}

func (a *basicAuth) Challenge() string { return `Basic realm="` + realm + `"` }

var _ Authenticator = (*basicAuth)(nil)
