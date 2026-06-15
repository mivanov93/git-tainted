package api

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the Prometheus counters/histograms for the server.
// A dedicated registry is used so tests/embedders can each have their own.
type Metrics struct {
	Registry *prometheus.Registry

	SyncTotal           *prometheus.CounterVec
	SyncErrorsTotal     *prometheus.CounterVec
	SyncDurationSeconds *prometheus.HistogramVec
	TagsTaintedTotal    prometheus.Counter
	VerifyDuration      *prometheus.HistogramVec
}

// NewMetrics creates a new Metrics with a fresh Prometheus registry.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	syncTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "git_tainted",
		Name:      "sync_total",
		Help:      "Total number of sync runs (by trigger and status).",
	}, []string{"trigger", "status"})

	syncErrors := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "git_tainted",
		Name:      "sync_errors_total",
		Help:      "Total number of sync runs that failed.",
	}, []string{"trigger"})

	syncDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "git_tainted",
		Name:      "sync_duration_seconds",
		Help:      "Duration of a sync run in seconds.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"trigger"})

	tagsTainted := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "git_tainted",
		Name:      "tags_tainted_total",
		Help:      "Total number of taint events appended (all reasons).",
	})

	verifyDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "git_tainted",
		Name:      "verify_latency_seconds",
		Help:      "Latency of GET /v1/verify in seconds.",
		Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
	}, []string{"status"})

	reg.MustRegister(syncTotal, syncErrors, syncDuration, tagsTainted, verifyDuration)

	return &Metrics{
		Registry:            reg,
		SyncTotal:           syncTotal,
		SyncErrorsTotal:     syncErrors,
		SyncDurationSeconds: syncDuration,
		TagsTaintedTotal:    tagsTainted,
		VerifyDuration:      verifyDuration,
	}
}
