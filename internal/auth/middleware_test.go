package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubAuth is a programmable Authenticator for middleware tests.
type stubAuth struct {
	principal string
	err       error
	challenge string
	calls     int
}

func (s *stubAuth) Authenticate(*http.Request) (string, error) {
	s.calls++
	return s.principal, s.err
}
func (s *stubAuth) Challenge() string { return s.challenge }

// echoPrincipal is a terminal handler that writes the context principal (or
// "<none>") so tests can assert what the middleware injected.
func echoPrincipal(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		p = "<none>"
	}
	_, _ = io.WriteString(w, p)
}

func TestMiddleware_ControlRouteEnforced(t *testing.T) {
	stub := &stubAuth{err: errBadCredential, challenge: "Bearer"}
	h := Middleware(stub)(http.HandlerFunc(echoPrincipal))

	// Every control route, with credentials that fail → 401.
	controlReqs := []struct{ method, path string }{
		{"POST", "/v1/remotes"},
		{"PATCH", "/v1/remotes/7"},
		{"DELETE", "/v1/remotes/7"},
		{"POST", "/v1/remotes/7/sync"},
		{"POST", "/v1/remotes/7/taint-events/9/ack"},
	}
	for _, c := range controlReqs {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
				t.Errorf("WWW-Authenticate = %q, want Bearer", got)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			if body := strings.TrimSpace(rec.Body.String()); body != `{"error":"unauthorized"}` {
				t.Errorf("body = %q, want unauthorized JSON", body)
			}
		})
	}
}

func TestMiddleware_OpenRoutesNeverGated(t *testing.T) {
	// An authenticator that would deny everything; open routes must bypass it.
	stub := &stubAuth{err: errBadCredential, challenge: "Bearer"}
	h := Middleware(stub)(http.HandlerFunc(echoPrincipal))

	openReqs := []struct{ method, path string }{
		{"GET", "/v1/verify"},
		{"GET", "/v1/remotes"},
		{"GET", "/v1/remotes/7"},
		{"GET", "/v1/remotes/7/syncs"},
		{"GET", "/v1/remotes/7/tags"},
		{"GET", "/v1/remotes/7/tags/v1.0.0"},
		{"GET", "/v1/remotes/7/taint-events"},
		{"GET", "/healthz"},
		{"GET", "/readyz"},
	}
	for _, c := range openReqs {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
			if rec.Code == http.StatusUnauthorized {
				t.Fatalf("open route %s %s returned 401", c.method, c.path)
			}
		})
	}
	if stub.calls != 0 {
		t.Fatalf("Authenticate was called %d times on open routes, want 0", stub.calls)
	}
}

func TestMiddleware_SuccessInjectsPrincipal(t *testing.T) {
	stub := &stubAuth{principal: "apikey:deadbeef"}
	h := Middleware(stub)(http.HandlerFunc(echoPrincipal))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/remotes", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "apikey:deadbeef" {
		t.Errorf("injected principal = %q, want apikey:deadbeef", rec.Body.String())
	}
}

func TestMiddleware_NonePassthrough(t *testing.T) {
	h := Middleware(None())(http.HandlerFunc(echoPrincipal))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/remotes", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("none control status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != AnonymousPrincipal {
		t.Errorf("none principal = %q, want %q", rec.Body.String(), AnonymousPrincipal)
	}
}

func TestMiddleware_NoChallengeHeaderWhenEmpty(t *testing.T) {
	// An authenticator with an empty challenge (denies) must still 401 but emit no
	// WWW-Authenticate header.
	stub := &stubAuth{err: errBadCredential, challenge: ""}
	h := Middleware(stub)(http.HandlerFunc(echoPrincipal))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/remotes", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q, want empty", got)
	}
}

// TestControlRoutesMatchOperations guards against drift between the canonical
// ControlOperations set and the middleware's route table.
func TestControlRoutesMatchOperations(t *testing.T) {
	if len(controlRoutes) != len(ControlOperations) {
		t.Fatalf("controlRoutes (%d) and ControlOperations (%d) differ in size", len(controlRoutes), len(ControlOperations))
	}
	for op := range controlRoutes {
		if !ControlOperations[op] {
			t.Errorf("controlRoutes has op %q absent from ControlOperations", op)
		}
	}
	for op := range ControlOperations {
		if _, ok := controlRoutes[op]; !ok {
			t.Errorf("ControlOperations has op %q absent from controlRoutes", op)
		}
	}
}
