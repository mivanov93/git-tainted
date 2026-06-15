package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func findRepoRoot(tb testing.TB) string {
	tb.Helper()
	dir, err := os.Getwd()
	if err != nil {
		tb.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			tb.Fatal("go.mod not found walking to repo root")
		}
		dir = parent
	}
}

func TestOpenAPISpecStub(t *testing.T) {
	root := findRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "spec", "openapi.yaml")) //nolint:gosec // G304: test fixture path built from findRepoRoot
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "openapi: 3.1.0") {
		t.Errorf("spec must declare OpenAPI 3.1.0")
	}
	if !strings.Contains(s, "/healthz") {
		t.Errorf("spec must contain the /healthz path")
	}
}

func TestOpenAPISpecHasRemotesPaths(t *testing.T) {
	root := findRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "spec", "openapi.yaml")) //nolint:gosec // G304: test fixture path built from findRepoRoot
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	s := string(data)
	for _, must := range []string{
		"/v1/remotes",
		"/v1/remotes/{remoteId}",
		"/v1/remotes/{remoteId}/tags",
		"/v1/remotes/{remoteId}/taint-events",
		"/v1/verify",
	} {
		if !strings.Contains(s, must) {
			t.Errorf("spec missing path %q", must)
		}
	}
}
