package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpsEndpoints(t *testing.T) {
	srv := httptest.NewServer(OpsHandler(nil, false))
	defer srv.Close()

	tests := []struct {
		name     string
		path     string
		wantCode int
		wantBody string
	}{
		{"healthz ok", "/healthz", http.StatusOK, "ok"},
		{"readyz ok", "/readyz", http.StatusOK, "ready"},
		{"unknown 404", "/nope", http.StatusNotFound, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(srv.URL + tc.path)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.wantCode {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantCode)
			}
			if tc.wantBody != "" {
				body, _ := io.ReadAll(resp.Body)
				if string(body) != tc.wantBody {
					t.Errorf("body = %q, want %q", string(body), tc.wantBody)
				}
			}
		})
	}
}

// TestPprofGating verifies that /debug/pprof/ returns 200 when pprofEnabled=true
// and 404 when pprofEnabled=false.
func TestPprofGating(t *testing.T) {
	t.Run("pprof enabled → 200", func(t *testing.T) {
		srv := httptest.NewServer(OpsHandler(nil, true))
		defer srv.Close()
		resp, err := http.Get(srv.URL + "/debug/pprof/")
		if err != nil {
			t.Fatalf("GET /debug/pprof/: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("pprof enabled: status=%d, want 200", resp.StatusCode)
		}
	})

	t.Run("pprof disabled → 404", func(t *testing.T) {
		srv := httptest.NewServer(OpsHandler(nil, false))
		defer srv.Close()
		resp, err := http.Get(srv.URL + "/debug/pprof/")
		if err != nil {
			t.Fatalf("GET /debug/pprof/: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("pprof disabled: status=%d, want 404", resp.StatusCode)
		}
	})
}

// TestMetricsHandler verifies that MetricsHandler serves GET /metrics.
func TestMetricsHandler(t *testing.T) {
	m := NewMetrics()
	srv := httptest.NewServer(MetricsHandler(m))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("MetricsHandler /metrics: status=%d, want 200", resp.StatusCode)
	}
}
