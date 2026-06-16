// Package auth provides optional authentication on the git-tainted control
// (mutating) endpoints. Reads and health probes are NEVER gated; only the five
// control operations — createRemote, updateRemote, deleteRemote, triggerSync,
// ackTaintEvent — are protected, and only when a non-"none" mode is configured
// (see the control-plane design spec §2).
//
// The package follows the project's two-impls-per-seam convention: the
// Authenticator interface has four selectable implementations (none, apikey,
// basic, jwks), all default-memory and dependency-light. FromConfig selects and
// validates one at startup; the Middleware enforces it before any handler or
// Store call is reached.
package auth

import (
	"context"
	"net/http"

	"github.com/mivanov93/git-tainted/internal/config"
)

// Authenticator verifies a request's credentials for a control operation.
//
// principal is a stable identity string used for audit (an API-key id, a basic
// username, or a JWT subject). err is a typed authentication failure — never a
// transport/5xx error; the enforcement Middleware maps any non-nil err to a 401.
type Authenticator interface {
	// Authenticate validates the request's credentials. On success it returns a
	// non-empty principal and a nil error. On any credential problem (missing,
	// malformed, wrong scheme, bad signature, expired, IdP unreachable) it returns
	// an error; the principal is then ignored.
	Authenticate(r *http.Request) (principal string, err error)
	// Challenge is the value for the WWW-Authenticate response header sent with a
	// 401 (e.g. "Bearer" or `Basic realm="git-tainted"`). May be empty (none mode).
	Challenge() string
}

// ControlOperations is the canonical set of protected operationIds. It is the
// single source of truth for "what requires auth"; the enforcement Middleware
// derives its route table from these so the protected set cannot drift from the
// router. Reads (verify, all GETs) and health probes are intentionally absent.
var ControlOperations = map[string]bool{
	"createRemote":  true,
	"updateRemote":  true,
	"deleteRemote":  true,
	"triggerSync":   true,
	"ackTaintEvent": true,
}

// AnonymousPrincipal is the principal recorded when auth is disabled (none mode).
const AnonymousPrincipal = "anonymous"

// realm is the protection space advertised in Basic/Bearer challenges.
const realm = "git-tainted"

// principalCtxKey is the unexported context key under which the authenticated
// principal is stored. Unexported so only this package can set it; readers use
// PrincipalFromContext.
type principalCtxKey struct{}

// withPrincipal returns a copy of ctx carrying the authenticated principal.
func withPrincipal(ctx context.Context, principal string) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, principal)
}

// PrincipalFromContext returns the authenticated principal previously stored by
// the enforcement Middleware, and whether one was present. Handlers use this to
// attribute audited mutations. When absent (e.g. an open route, or a request
// that never passed through the middleware) it returns ("", false).
func PrincipalFromContext(ctx context.Context) (string, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(string)
	return p, ok
}

// noneAuth is the pass-through authenticator: it allows every request and
// attributes it to the anonymous principal. It reproduces the pre-auth posture
// (loopback bind + trusted edge proxy) exactly. Its Challenge is empty.
type noneAuth struct{}

// None returns the pass-through authenticator used when GT_AUTH_MODE=none (the
// default) and as the explicit "no auth" value for server callers/tests.
func None() Authenticator { return noneAuth{} }

func (noneAuth) Authenticate(*http.Request) (string, error) { return AnonymousPrincipal, nil }
func (noneAuth) Challenge() string                          { return "" }

// Compile-time assertion that noneAuth satisfies the interface.
var _ Authenticator = noneAuth{}

// modeOf returns the configured auth mode, defaulting to "none".
func modeOf(cfg *config.Config) string {
	if cfg == nil || cfg.AuthMode == "" {
		return config.AuthModeNone
	}
	return cfg.AuthMode
}
