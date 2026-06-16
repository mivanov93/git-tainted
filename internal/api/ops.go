// Package api wires the HTTP server: ops probes now (healthz/readyz), and the
// OpenAPI-generated ServerInterface + domain handlers in later phases. All
// handlers are read-only-safe where the spec requires (verify is GET-only).
package api

import (
	"context"
	"net/http"
	"net/http/pprof" //nolint:gosec // G108: pprof is guarded by PprofEnabled (default false), not always on

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mivanov93/git-tainted/internal/model"
)

// OpsHandler returns the operational probe mux:
//   - GET /healthz — liveness (always 200)
//   - GET /readyz  — readiness (pings the Store; 200 if ok, 503 if nil/fail)
//   - /debug/pprof/* — runtime profiling (only when pprofEnabled is true)
//
// store may be nil; when nil /readyz returns 200 unconditionally.
// /metrics is NOT served on this handler — use MetricsHandler on a dedicated
// metrics listener instead.
func OpsHandler(store model.Store, pprofEnabled bool) http.Handler {
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

	if pprofEnabled {
		// pprof endpoints (§14 ops) — only when GT_PPROF_ENABLED=true.
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	return mux
}

// MetricsHandler returns an http.Handler that serves GET /metrics via Prometheus.
// It is intended to be mounted on a DEDICATED metrics listener (GT_METRICS_ADDR),
// never on the public API port.
func MetricsHandler(m *Metrics) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))
	return mux
}
