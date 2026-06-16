package auth

import "errors"

// These sentinels classify why authentication failed. The enforcement Middleware
// maps ALL of them to an identical 401 response — they are distinguished only for
// internal logging and tests, never surfaced to the client (no oracle that
// distinguishes "missing" from "bad" from "IdP down").
var (
	// errMissingCredential: no credential was presented (no/empty header).
	errMissingCredential = errors.New("auth: missing credential")
	// errBadCredential: a credential was presented but did not verify (wrong key,
	// wrong password, bad/expired/forged token, disallowed algorithm).
	errBadCredential = errors.New("auth: invalid credential")
	// errIdPUnavailable: the JWKS endpoint could not be reached / had no usable
	// key, so verification fails closed (treated as denied, logged as a warning).
	errIdPUnavailable = errors.New("auth: identity provider unavailable")
)
