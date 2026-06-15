// Package api wires the HTTP server: ops probes now (healthz/readyz), and the
// OpenAPI-generated ServerInterface + domain handlers in later phases. All
// handlers are read-only-safe where the spec requires (verify is GET-only).
package api

import (
	"context"
	"net/http"
	"net/http/pprof" //nolint:gosec // G108: pprof is served on a dedicated metrics addr, not the public addr

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mivanov93/git-tainted/internal/model"
)

// OpsHandler returns the operational probe mux: /healthz (liveness) and /readyz
// (readiness, always 200 — no store). This form is kept for backward compat with
// existing unit tests; for production use OpsHandlerFull which wires the store.
func OpsHandler() http.Handler {
	return OpsHandlerFull(nil, nil)
}

// OpsHandlerFull returns the operational probe mux with:
//   - GET /healthz — liveness (always 200)
//   - GET /readyz  — readiness (pings the Store; 200 if ok, 503 if nil/fail)
//   - GET /metrics — Prometheus (if m != nil)
//   - /debug/pprof/ — runtime profiling (always mounted; caller restricts to internal addr)
//
// store may be nil; when nil /readyz returns 200 unconditionally.
// m may be nil; when nil /metrics returns 404.
func OpsHandlerFull(store model.Store, m *Metrics) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if store != nil {
			if err := store.Ping(context.Background()); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("not ready: " + err.Error()))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	if m != nil {
		mux.Handle("GET /metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))
	}

	// pprof endpoints (§14 ops).
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	return mux
}
