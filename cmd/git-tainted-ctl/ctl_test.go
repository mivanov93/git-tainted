// ctl_test.go — run()-level tests for git-tainted-ctl.
// Tests use httptest.Server stubs; no real network, no git.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---- test helpers ----------------------------------------------------------

// capture runs run() capturing stdout+stderr.
func capture(args []string, environ []string) (stdout, stderr string, code int) {
	var outBuf, errBuf bytes.Buffer
	code = run(args, environ, &outBuf, &errBuf)
	return outBuf.String(), errBuf.String(), code
}

// ---- --version / --help ----------------------------------------------------

func TestVersion(t *testing.T) {
	out, _, code := capture([]string{"--version"}, nil)
	if code != 0 {
		t.Fatalf("want exit 0, got %d", code)
	}
	if !strings.HasPrefix(out, "git-tainted-ctl ") {
		t.Errorf("want version prefix, got %q", out)
	}
}

func TestVersionShort(t *testing.T) {
	out, _, code := capture([]string{"-v"}, nil)
	if code != 0 {
		t.Fatalf("want exit 0, got %d", code)
	}
	if !strings.HasPrefix(out, "git-tainted-ctl ") {
		t.Errorf("want version prefix, got %q", out)
	}
}

func TestHelp(t *testing.T) {
	// --help writes to stderr via the flag set's output; the top-level flag set
	// triggers fs.Usage which writes to stderr directly.
	out, errOut, code := capture([]string{"--help"}, nil)
	if code != 0 {
		t.Fatalf("want exit 0, got %d", code)
	}
	combined := out + errOut
	if !strings.Contains(combined, "remote add") {
		t.Errorf("help should mention 'remote add', combined output: %q", combined)
	}
}

func TestNoCommand(t *testing.T) {
	_, _, code := capture([]string{}, nil)
	if code != exitUsage {
		t.Fatalf("want exit %d, got %d", exitUsage, code)
	}
}

func TestUnknownCommand(t *testing.T) {
	_, _, code := capture([]string{"--server", "http://127.0.0.1:1", "bogus"}, nil)
	if code != exitUsage {
		t.Fatalf("want exit %d, got %d", exitUsage, code)
	}
}

// ---- transport guard -------------------------------------------------------

func TestTransportGuardRefusesNonLoopback(t *testing.T) {
	_, stderr, code := capture([]string{"--server", "http://example.com:8080", "remote", "list"}, nil)
	if code != exitUsage {
		t.Fatalf("want exit %d, got %d", exitUsage, code)
	}
	if !strings.Contains(stderr, "refusing plaintext") {
		t.Errorf("expected refusing plaintext message, got %q", stderr)
	}
}

func TestTransportGuardAllowsLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"items":[]}`)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "remote", "list"}, nil)
	if code != exitOK {
		t.Fatalf("loopback should be allowed, got exit %d", code)
	}
}

func TestTransportGuardAllowsHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"items":[]}`)
	}))
	defer srv.Close()

	// We can't use the TLS server with our default transport without cert config,
	// but we can confirm the URL check passes (transport error, not refusal).
	// The checkServerURL call should not return an error for https://.
	err := checkServerURL(srv.URL, false)
	if err != nil {
		t.Errorf("https should be allowed without --insecure: %v", err)
	}
}

func TestTransportGuardInsecureFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"items":[]}`)
	}))
	defer srv.Close()

	// Replace srv.URL host with a non-loopback-looking one is not possible in test,
	// but we can verify the flag logic:
	err := checkServerURL("http://external.example.com:8080", true)
	if err != nil {
		t.Errorf("--insecure should allow plaintext: %v", err)
	}
}

func TestTransportGuardInsecureEnv(t *testing.T) {
	err := checkServerURL("http://external.example.com:8080", false)
	if err == nil {
		t.Error("should refuse plaintext without insecure")
	}
	// With insecure = true (from env simulation).
	err = checkServerURL("http://external.example.com:8080", true)
	if err != nil {
		t.Errorf("should allow plaintext with insecure=true: %v", err)
	}
}

// ---- transport error → exit 2 ----------------------------------------------

func TestTransportError(t *testing.T) {
	// Port 1 is almost certainly refused on loopback.
	_, stderr, code := capture([]string{"--server", "http://127.0.0.1:1", "remote", "list"}, nil)
	if code != exitUsage {
		t.Fatalf("transport error want exit %d, got %d\nstderr: %s", exitUsage, code, stderr)
	}
	if !strings.Contains(stderr, "error:") {
		t.Errorf("expected error message in stderr, got %q", stderr)
	}
}

// ---- auth header selection -------------------------------------------------

func TestAuthAPIKeyFlag(t *testing.T) {
	var gotAuth, gotXKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotXKey = r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"items":[]}`)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "--api-key", "mykey123", "remote", "list"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotAuth != "Bearer mykey123" {
		t.Errorf("Authorization want %q got %q", "Bearer mykey123", gotAuth)
	}
	if gotXKey != "mykey123" {
		t.Errorf("X-Api-Key want %q got %q", "mykey123", gotXKey)
	}
}

func TestAuthAPIKeyEnv(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"items":[]}`)
	}))
	defer srv.Close()

	_, _, code := capture(
		[]string{"--server", srv.URL, "remote", "list"},
		[]string{"GT_API_KEY=envkey"},
	)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotAuth != "Bearer envkey" {
		t.Errorf("want Bearer envkey, got %q", gotAuth)
	}
}

func TestAuthTokenFlag(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"items":[]}`)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "--token", "my.jwt.token", "remote", "list"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotAuth != "Bearer my.jwt.token" {
		t.Errorf("want Bearer my.jwt.token, got %q", gotAuth)
	}
}

func TestAuthTokenEnv(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"items":[]}`)
	}))
	defer srv.Close()

	_, _, code := capture(
		[]string{"--server", srv.URL, "remote", "list"},
		[]string{"GT_TOKEN=env.jwt.here"},
	)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotAuth != "Bearer env.jwt.here" {
		t.Errorf("want Bearer env.jwt.here, got %q", gotAuth)
	}
}

func TestAuthBasicFlag(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"items":[]}`)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "--basic", "admin:secret", "remote", "list"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	// base64("admin:secret") = "YWRtaW46c2VjcmV0"
	if gotAuth != "Basic YWRtaW46c2VjcmV0" {
		t.Errorf("want Basic YWRtaW46c2VjcmV0, got %q", gotAuth)
	}
}

func TestAuthBasicEnv(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"items":[]}`)
	}))
	defer srv.Close()

	_, _, code := capture(
		[]string{"--server", srv.URL, "remote", "list"},
		[]string{"GT_BASIC_AUTH=op:pass"},
	)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("want Basic auth, got %q", gotAuth)
	}
}

func TestAuthNone(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"items":[]}`)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "remote", "list"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotAuth != "" {
		t.Errorf("want no auth header, got %q", gotAuth)
	}
}

// Flag wins over env.
func TestAuthFlagWinsOverEnv(t *testing.T) {
	var gotAuth, gotXKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotXKey = r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"items":[]}`)
	}))
	defer srv.Close()

	_, _, code := capture(
		[]string{"--server", srv.URL, "--api-key", "flagkey", "remote", "list"},
		[]string{"GT_TOKEN=envjwt"}, // env token should be ignored
	)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotAuth != "Bearer flagkey" {
		t.Errorf("flag should win: want Bearer flagkey, got %q", gotAuth)
	}
	if gotXKey != "flagkey" {
		t.Errorf("X-Api-Key should be set: want flagkey, got %q", gotXKey)
	}
}

// ---- exit code mapping -----------------------------------------------------

func TestExitCode404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_, _ = fmt.Fprint(w, `{"error":"not found"}`)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "remote", "get", "99"}, nil)
	if code != exitNotFound {
		t.Fatalf("want exit %d, got %d", exitNotFound, code)
	}
}

func TestExitCode401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		_, _ = fmt.Fprint(w, `{"error":"unauthorized"}`)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "remote", "list"}, nil)
	if code != exitUnauth {
		t.Fatalf("want exit %d, got %d", exitUnauth, code)
	}
}

func TestExitCode403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		_, _ = fmt.Fprint(w, `{"error":"forbidden"}`)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "remote", "list"}, nil)
	if code != exitUnauth {
		t.Fatalf("want exit %d, got %d", exitUnauth, code)
	}
}

func TestExitCode409(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(409)
		_, _ = fmt.Fprint(w, `{"error":"conflict"}`)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "remote", "add", "https://github.com/foo/bar"}, nil)
	if code != exitConflict {
		t.Fatalf("want exit %d, got %d", exitConflict, code)
	}
}

func TestExitCode500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		_, _ = fmt.Fprint(w, `{"error":"internal server error"}`)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "remote", "list"}, nil)
	if code != exitServerError {
		t.Fatalf("want exit %d, got %d", exitServerError, code)
	}
}

// ---- remote add ------------------------------------------------------------

func TestRemoteAdd(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody wireCreateRemoteReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		resp := wireRemote{ID: 42, NormalizedURL: "https://github.com/foo/bar", Status: "active", Transport: "https"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	out, _, code := capture([]string{"--server", srv.URL, "remote", "add", "https://github.com/foo/bar"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotMethod != "POST" {
		t.Errorf("want POST, got %s", gotMethod)
	}
	if gotPath != "/v1/remotes" {
		t.Errorf("want /v1/remotes, got %s", gotPath)
	}
	if gotBody.URL != "https://github.com/foo/bar" {
		t.Errorf("want url in body, got %q", gotBody.URL)
	}
	if !strings.Contains(out, "id=42") {
		t.Errorf("output should contain id=42, got %q", out)
	}
}

func TestRemoteAddWithInterval(t *testing.T) {
	var gotBody wireCreateRemoteReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		resp := wireRemote{ID: 1, NormalizedURL: "https://github.com/a/b", Status: "active", Transport: "https"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "remote", "add", "https://github.com/a/b", "--interval", "5m"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	want := int64(5 * time.Minute)
	if gotBody.SyncIntervalNS == nil || *gotBody.SyncIntervalNS != want {
		t.Errorf("want SyncIntervalNS=%d, got %v", want, gotBody.SyncIntervalNS)
	}
}

// ---- remote list -----------------------------------------------------------

func TestRemoteList(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		resp := wireRemoteList{Items: []wireRemote{
			{ID: 1, NormalizedURL: "https://github.com/a/b", Status: "active", Transport: "https"},
			{ID: 2, NormalizedURL: "https://github.com/c/d", Status: "degraded", Transport: "https"},
		}}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	out, _, code := capture([]string{"--server", srv.URL, "remote", "list"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotMethod != "GET" {
		t.Errorf("want GET, got %s", gotMethod)
	}
	if gotPath != "/v1/remotes" {
		t.Errorf("want /v1/remotes, got %s", gotPath)
	}
	if !strings.Contains(out, "github.com/a/b") {
		t.Errorf("output should contain URL, got %q", out)
	}
}

func TestRemoteListJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := wireRemoteList{Items: []wireRemote{
			{ID: 1, NormalizedURL: "https://github.com/a/b", Status: "active", Transport: "https"},
		}}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	out, _, code := capture([]string{"--server", srv.URL, "remote", "list", "--json"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var parsed wireRemoteList
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output not valid JSON: %v\nout: %s", err, out)
	}
	if len(parsed.Items) != 1 {
		t.Errorf("want 1 item, got %d", len(parsed.Items))
	}
}

// ---- remote get ------------------------------------------------------------

func TestRemoteGetByID(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		resp := wireRemote{ID: 7, NormalizedURL: "https://github.com/x/y", Status: "active", Transport: "https"}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	out, _, code := capture([]string{"--server", srv.URL, "remote", "get", "7"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotPath != "/v1/remotes/7" {
		t.Errorf("want /v1/remotes/7, got %s", gotPath)
	}
	if !strings.Contains(out, "github.com/x/y") {
		t.Errorf("output should contain URL, got %q", out)
	}
}

func TestRemoteGetByURL(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path + "?" + r.URL.RawQuery
		resp := wireRemoteList{Items: []wireRemote{
			{ID: 3, NormalizedURL: "https://github.com/x/y", Status: "active", Transport: "https"},
		}}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "remote", "get", "https://github.com/x/y"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(gotPath, "/v1/remotes?") {
		t.Errorf("URL form should use /v1/remotes?url=, got %s", gotPath)
	}
	if !strings.Contains(gotPath, "url=") {
		t.Errorf("should include url= param, got %s", gotPath)
	}
}

// ---- remote update ---------------------------------------------------------

func TestRemoteUpdate(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody wireUpdateRemoteReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		resp := wireRemote{ID: 5, NormalizedURL: "https://github.com/a/b", Status: "paused", Transport: "https"}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	out, _, code := capture([]string{"--server", srv.URL, "remote", "update", "5", "--enabled=false"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotMethod != "PATCH" {
		t.Errorf("want PATCH, got %s", gotMethod)
	}
	if gotPath != "/v1/remotes/5" {
		t.Errorf("want /v1/remotes/5, got %s", gotPath)
	}
	if gotBody.Status == nil || *gotBody.Status != "paused" {
		t.Errorf("want status=paused in body, got %v", gotBody.Status)
	}
	if !strings.Contains(out, "status=paused") {
		t.Errorf("output should mention status, got %q", out)
	}
}

func TestRemoteUpdateInterval(t *testing.T) {
	var gotBody wireUpdateRemoteReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		resp := wireRemote{ID: 5, NormalizedURL: "https://github.com/a/b", Status: "active", Transport: "https"}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "remote", "update", "5", "--interval=10m"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	want := int64(10 * time.Minute)
	if gotBody.SyncIntervalNS == nil || *gotBody.SyncIntervalNS != want {
		t.Errorf("want SyncIntervalNS=%d, got %v", want, gotBody.SyncIntervalNS)
	}
}

// ---- remote rm -------------------------------------------------------------

func TestRemoteRm(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(204)
	}))
	defer srv.Close()

	out, _, code := capture([]string{"--server", srv.URL, "remote", "rm", "9"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotMethod != "DELETE" {
		t.Errorf("want DELETE, got %s", gotMethod)
	}
	if gotPath != "/v1/remotes/9" {
		t.Errorf("want /v1/remotes/9, got %s", gotPath)
	}
	if !strings.Contains(out, "deleted") {
		t.Errorf("output should say deleted, got %q", out)
	}
}

// ---- sync ------------------------------------------------------------------

func TestSync(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(202)
	}))
	defer srv.Close()

	out, _, code := capture([]string{"--server", srv.URL, "sync", "3"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotMethod != "POST" {
		t.Errorf("want POST, got %s", gotMethod)
	}
	if gotPath != "/v1/remotes/3/sync" {
		t.Errorf("want /v1/remotes/3/sync, got %s", gotPath)
	}
	if !strings.Contains(out, "202") {
		t.Errorf("output should mention 202, got %q", out)
	}
}

// ---- syncs -----------------------------------------------------------------

func TestSyncs(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		resp := wireSyncAuditList{Items: []wireSyncEntry{
			{ID: 1, RemoteID: 3, Trigger: "manual", Status: "ok", StartedNS: 1000000000},
		}}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	out, _, code := capture([]string{"--server", srv.URL, "syncs", "3"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotMethod != "GET" {
		t.Errorf("want GET, got %s", gotMethod)
	}
	if gotPath != "/v1/remotes/3/syncs" {
		t.Errorf("want /v1/remotes/3/syncs, got %s", gotPath)
	}
	if !strings.Contains(out, "manual") {
		t.Errorf("output should contain trigger, got %q", out)
	}
}

func TestSyncsJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := wireSyncAuditList{Items: []wireSyncEntry{
			{ID: 1, RemoteID: 3, Trigger: "manual", Status: "ok", StartedNS: 1000000000},
		}}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	out, _, code := capture([]string{"--server", srv.URL, "syncs", "3", "--json"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var parsed wireSyncAuditList
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
}

// ---- tags ------------------------------------------------------------------

func TestTags(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		resp := wireTagList{Items: []wireTag{
			{ID: 1, RemoteID: 2, TagName: "v1.0.0", Tainted: false, Deleted: false},
		}}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	out, _, code := capture([]string{"--server", srv.URL, "tags", "2"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotPath != "/v1/remotes/2/tags" {
		t.Errorf("want /v1/remotes/2/tags, got %s", gotPath)
	}
	if !strings.Contains(out, "v1.0.0") {
		t.Errorf("output should contain tag name, got %q", out)
	}
}

func TestTagsJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := wireTagList{Items: []wireTag{
			{ID: 1, RemoteID: 2, TagName: "v1.0.0"},
		}}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	out, _, code := capture([]string{"--server", srv.URL, "tags", "2", "--json"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var parsed wireTagList
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
}

// ---- taint list ------------------------------------------------------------

func TestTaintList(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		resp := wireTaintEventList{Items: []wireTaintEvent{
			{ID: 10, RemoteID: 2, RefID: 5, Reason: "tag_oid_changed", DetectedAtNS: 1000000000},
		}}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	out, _, code := capture([]string{"--server", srv.URL, "taint", "list", "2"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotPath != "/v1/remotes/2/taint-events" {
		t.Errorf("want /v1/remotes/2/taint-events, got %s", gotPath)
	}
	if !strings.Contains(out, "tag_oid_changed") {
		t.Errorf("output should contain reason, got %q", out)
	}
}

func TestTaintListJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := wireTaintEventList{Items: []wireTaintEvent{
			{ID: 10, RemoteID: 2, RefID: 5, Reason: "tag_oid_changed", DetectedAtNS: 1000000000},
		}}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	out, _, code := capture([]string{"--server", srv.URL, "taint", "list", "2", "--json"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var parsed wireTaintEventList
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
}

// ---- taint ack -------------------------------------------------------------

func TestTaintAck(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody wireAckReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(204)
	}))
	defer srv.Close()

	out, _, code := capture([]string{
		"--server", srv.URL, "taint", "ack", "2", "10", "--by", "ops-team", "--note", "investigated",
	}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotMethod != "POST" {
		t.Errorf("want POST, got %s", gotMethod)
	}
	if gotPath != "/v1/remotes/2/taint-events/10/ack" {
		t.Errorf("want /v1/remotes/2/taint-events/10/ack, got %s", gotPath)
	}
	if gotBody.AckedBy != "ops-team" {
		t.Errorf("want acked_by=ops-team, got %q", gotBody.AckedBy)
	}
	if gotBody.AckNote != "investigated" {
		t.Errorf("want ack_note=investigated, got %q", gotBody.AckNote)
	}
	if !strings.Contains(out, "acknowledged") {
		t.Errorf("output should say acknowledged, got %q", out)
	}
}

func TestTaintAckConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(409)
		_, _ = fmt.Fprint(w, `{"error":"already acknowledged"}`)
	}))
	defer srv.Close()

	_, _, code := capture([]string{
		"--server", srv.URL, "taint", "ack", "2", "10", "--by", "ops",
	}, nil)
	if code != exitConflict {
		t.Fatalf("want exit %d, got %d", exitConflict, code)
	}
}

func TestTaintAckMissingBy(t *testing.T) {
	_, stderr, code := capture([]string{
		"--server", "http://127.0.0.1:8080", "taint", "ack", "2", "10",
	}, nil)
	if code != exitUsage {
		t.Fatalf("want exit %d, got %d", exitUsage, code)
	}
	if !strings.Contains(stderr, "--by") {
		t.Errorf("should mention --by requirement, got %q", stderr)
	}
}

// ---- global --json flag propagation ----------------------------------------

func TestGlobalJSONFlagPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := wireRemoteList{Items: []wireRemote{
			{ID: 1, NormalizedURL: "https://github.com/a/b", Status: "active", Transport: "https"},
		}}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	// --json placed before subcommand (global flag).
	out, _, code := capture([]string{"--server", srv.URL, "--json", "remote", "list"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var parsed wireRemoteList
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("--json global should produce JSON output: %v\nout: %s", err, out)
	}
}

// ---- GT_CTL_SERVER env -----------------------------------------------------

func TestServerEnv(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"items":[]}`)
	}))
	defer srv.Close()

	_, _, code := capture(
		[]string{"remote", "list"},
		[]string{"GT_CTL_SERVER=" + srv.URL},
	)
	if code != exitOK {
		t.Fatalf("GT_CTL_SERVER env not picked up, exit %d", code)
	}
}

// ---- usage errors ----------------------------------------------------------

func TestRemoteAddMissingURL(t *testing.T) {
	_, _, code := capture([]string{"--server", "http://127.0.0.1:8080", "remote", "add"}, nil)
	if code != exitUsage {
		t.Fatalf("want exit %d, got %d", exitUsage, code)
	}
}

func TestRemoteGetMissingArg(t *testing.T) {
	_, _, code := capture([]string{"--server", "http://127.0.0.1:8080", "remote", "get"}, nil)
	if code != exitUsage {
		t.Fatalf("want exit %d, got %d", exitUsage, code)
	}
}

func TestRemoteUpdateNoFields(t *testing.T) {
	_, _, code := capture([]string{"--server", "http://127.0.0.1:8080", "remote", "update", "1"}, nil)
	if code != exitUsage {
		t.Fatalf("want exit %d, got %d", exitUsage, code)
	}
}

func TestSyncMissingID(t *testing.T) {
	_, _, code := capture([]string{"--server", "http://127.0.0.1:8080", "sync"}, nil)
	if code != exitUsage {
		t.Fatalf("want exit %d, got %d", exitUsage, code)
	}
}

func TestSyncsMissingID(t *testing.T) {
	_, _, code := capture([]string{"--server", "http://127.0.0.1:8080", "syncs"}, nil)
	if code != exitUsage {
		t.Fatalf("want exit %d, got %d", exitUsage, code)
	}
}

func TestTagsMissingID(t *testing.T) {
	_, _, code := capture([]string{"--server", "http://127.0.0.1:8080", "tags"}, nil)
	if code != exitUsage {
		t.Fatalf("want exit %d, got %d", exitUsage, code)
	}
}

func TestTaintMissingSubcommand(t *testing.T) {
	_, _, code := capture([]string{"--server", "http://127.0.0.1:8080", "taint"}, nil)
	if code != exitUsage {
		t.Fatalf("want exit %d, got %d", exitUsage, code)
	}
}

func TestTaintAckMissingArgs(t *testing.T) {
	_, _, code := capture([]string{"--server", "http://127.0.0.1:8080", "taint", "ack"}, nil)
	if code != exitUsage {
		t.Fatalf("want exit %d, got %d", exitUsage, code)
	}
}

// ---- request body / content-type -------------------------------------------

func TestRequestBodyContentType(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		resp := wireRemote{ID: 1, NormalizedURL: "https://github.com/a/b", Status: "active", Transport: "https"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	_, _, code := capture([]string{"--server", srv.URL, "remote", "add", "https://github.com/a/b"}, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if gotCT != "application/json" {
		t.Errorf("want Content-Type: application/json, got %q", gotCT)
	}
}

// ---- IO utilities (writeJSON) ----------------------------------------------

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	var errBuf bytes.Buffer
	code := writeJSON(&buf, &errBuf, map[string]int{"x": 1})
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	// Result should be valid JSON.
	var m map[string]int
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if m["x"] != 1 {
		t.Errorf("want x=1, got %v", m)
	}
}

func TestWriteJSONError(t *testing.T) {
	// Writing to a closed writer should produce an error exit.
	code := writeJSON(io.Discard, io.Discard, make(chan int)) // chan is not JSON-serialisable
	if code != exitUsage {
		t.Fatalf("want exit %d for bad input, got %d", exitUsage, code)
	}
}
