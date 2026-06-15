package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpsEndpoints(t *testing.T) {
	srv := httptest.NewServer(OpsHandler())
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
