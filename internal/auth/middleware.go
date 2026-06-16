package auth

import (
	"net/http"
)

// controlRoutes maps each protected operationId to its method+path ServeMux
// pattern (the generated router's exact patterns, including the {remoteId} /
// {eventId} wildcards). Registering ONLY these method-specific patterns in the
// control mux means ServeMux.Handler reports a non-empty pattern for exactly the
// five mutating operations and empty for every open read on the same paths
// (verified: a GET on /v1/remotes does not match "POST /v1/remotes").
//
// The map keys are drawn from ControlOperations so the route table and the
// canonical protected set cannot drift apart.
var controlRoutes = map[string]string{
	"createRemote":  "POST /v1/remotes",
	"updateRemote":  "PATCH /v1/remotes/{remoteId}",
	"deleteRemote":  "DELETE /v1/remotes/{remoteId}",
	"triggerSync":   "POST /v1/remotes/{remoteId}/sync",
	"ackTaintEvent": "POST /v1/remotes/{remoteId}/taint-events/{eventId}/ack",
}

// newControlMux builds the route-matching mux used by the enforcement middleware.
// Its handlers are never executed — only ServeMux's pattern matching is used — so
// each registers a no-op. It panics if controlRoutes and ControlOperations ever
// disagree, turning a refactor drift into an immediate, loud startup failure.
func newControlMux() *http.ServeMux {
	if len(controlRoutes) != len(ControlOperations) {
		panic("auth: controlRoutes and ControlOperations have diverged")
	}
	noop := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	mux := http.NewServeMux()
	for op, pattern := range controlRoutes {
		if !ControlOperations[op] {
			panic("auth: controlRoutes contains a non-control operation: " + op)
		}
		mux.Handle(pattern, noop)
	}
	return mux
}

// Middleware returns an http.Handler middleware that enforces authn on the five
// control operations and passes everything else through untouched.
//
// For a request whose method+path matches a control route, it calls
// Authenticate BEFORE next is invoked; on failure it writes 401 +
// WWW-Authenticate + a JSON {"error":"unauthorized"} body and returns (next, and
// therefore the handler and Store, are never reached). On success it injects the
// principal into the request context for audit. Open routes (and all requests
// under none mode, whose Authenticate always succeeds) flow straight to next.
//
// The middleware is installed uniformly for every mode — including none — so the
// wiring is identical and testable; under none the control-route branch still
// runs but Authenticate is a no-op that always allows.
func Middleware(authn Authenticator) func(http.Handler) http.Handler {
	mux := newControlMux()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, pat := mux.Handler(r); pat != "" {
				principal, err := authn.Authenticate(r)
				if err != nil {
					writeUnauthorized(w, authn.Challenge())
					return
				}
				r = r.WithContext(withPrincipal(r.Context(), principal))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// writeUnauthorized writes the canonical 401 response: a WWW-Authenticate header
// (when the authenticator advertises a challenge) and a small JSON body. The body
// is a fixed string — identical for every failure cause — so no information about
// why auth failed (missing vs bad vs IdP-down) leaks to the client.
func writeUnauthorized(w http.ResponseWriter, challenge string) {
	if challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}
