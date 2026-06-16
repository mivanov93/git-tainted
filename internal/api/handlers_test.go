package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/testutil"
)

func newAPITestServer(tb testing.TB) (*httptest.Server, model.Store) {
	tb.Helper()
	// testutil.NewTestStore opens an in-temp-file SQLite store and applies the
	// embedded migrations (no db/ folder needed).
	s := testutil.NewTestStore(tb)

	clk := &fixedClock{ns: 1_718_000_000_000_000_000}
	srv := httptest.NewServer(NewServer(s, clk, nil))
	tb.Cleanup(srv.Close)
	return srv, s
}

type fixedClock struct{ ns int64 }

func (c *fixedClock) NowNS() int64 { return c.ns }

func itoa(n int64) string { return fmt.Sprintf("%d", n) }

// TestCreateRemote_HTTP verifies POST /v1/remotes creates a remote and returns 201.
func TestCreateRemote_HTTP(t *testing.T) {
	srv, _ := newAPITestServer(t)

	body := `{"url":"https://github.com/org/repo.git","transport":"https"}`
	resp, err := http.Post(srv.URL+"/v1/remotes", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /v1/remotes: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["normalized_url"] != "https://github.com/org/repo.git" {
		t.Errorf("normalized_url = %v, want https://github.com/org/repo.git", got["normalized_url"])
	}
	if got["id"] == nil || got["id"] == float64(0) {
		t.Errorf("id must be non-zero, got %v", got["id"])
	}
}

// TestCreateRemote_DupURL_409 verifies duplicate normalized_url → 409.
func TestCreateRemote_DupURL_409(t *testing.T) {
	srv, _ := newAPITestServer(t)

	body := `{"url":"https://github.com/org/repo.git","transport":"https"}`
	r1, _ := http.Post(srv.URL+"/v1/remotes", "application/json", bytes.NewBufferString(body))
	_ = r1.Body.Close()
	resp, _ := http.Post(srv.URL+"/v1/remotes", "application/json", bytes.NewBufferString(body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("dup url: status = %d, want 409", resp.StatusCode)
	}
}

// TestCreateRemote_InvalidURL_422 verifies file:// url → 422.
func TestCreateRemote_InvalidURL_422(t *testing.T) {
	srv, _ := newAPITestServer(t)

	body := `{"url":"file:///tmp/repo","transport":"https"}`
	resp, _ := http.Post(srv.URL+"/v1/remotes", "application/json", bytes.NewBufferString(body))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("bad url: status = %d, want 422", resp.StatusCode)
	}
}

// TestGetRemote_NotFound_404 verifies GET /v1/remotes/9999 → 404.
func TestGetRemote_NotFound_404(t *testing.T) {
	srv, _ := newAPITestServer(t)
	resp, _ := http.Get(srv.URL + "/v1/remotes/9999")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// TestListRemotes_Empty verifies GET /v1/remotes on an empty store → 200 + empty items.
func TestListRemotes_Empty(t *testing.T) {
	srv, _ := newAPITestServer(t)
	resp, err := http.Get(srv.URL + "/v1/remotes")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	items := got["items"].([]any)
	if len(items) != 0 {
		t.Errorf("items len = %d, want 0", len(items))
	}
}

// TestDeleteRemote_HTTP verifies soft-delete returns 204 and the remote is still GET-able.
func TestDeleteRemote_HTTP(t *testing.T) {
	srv, _ := newAPITestServer(t)

	// Create remote.
	body := `{"url":"https://github.com/org/repo.git","transport":"https"}`
	resp, _ := http.Post(srv.URL+"/v1/remotes", "application/json", bytes.NewBufferString(body))
	var created map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	_ = resp.Body.Close()
	rid := int64(created["id"].(float64))

	// Soft-delete.
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/v1/remotes/"+itoa(rid), nil)
	resp2, _ := http.DefaultClient.Do(req)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", resp2.StatusCode)
	}

	// Still retrievable (soft-delete sets removed_at_ns).
	resp3, _ := http.Get(srv.URL + "/v1/remotes/" + itoa(rid))
	defer func() { _ = resp3.Body.Close() }()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("after soft-delete: status = %d, want 200", resp3.StatusCode)
	}
}

// TestVerify_NotTracked verifies that an unknown remote returns not_tracked.
func TestVerify_NotTracked(t *testing.T) {
	srv, _ := newAPITestServer(t)

	resp, _ := http.Get(srv.URL + "/v1/verify?remote=https://github.com/unknown/repo.git&tag=v1.0.0")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] != "not_tracked" {
		t.Errorf("status = %v, want not_tracked", got["status"])
	}
}

// TestVerify_DoesntExist verifies that a known remote but unknown tag returns doesnt_exist.
func TestVerify_DoesntExist(t *testing.T) {
	srv, _ := newAPITestServer(t)

	// Create remote.
	body := `{"url":"https://github.com/org/repo.git","transport":"https"}`
	resp, _ := http.Post(srv.URL+"/v1/remotes", "application/json", bytes.NewBufferString(body))
	_ = resp.Body.Close()

	resp2, _ := http.Get(srv.URL + "/v1/verify?remote=https://github.com/org/repo.git&tag=v1.0.0")
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp2.StatusCode)
	}
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	var got2 map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&got2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got2["status"] != "doesnt_exist" {
		t.Errorf("status = %v, want doesnt_exist", got2["status"])
	}
}

// TestTracerRegisterAndVerify is the end-to-end tracer:
//  1. POST /v1/remotes → 201
//  2. POST /v1/remotes (same url) → 409
//  3. GET /v1/remotes → 200, 1 item
//  4. DELETE /v1/remotes/{rid} → 204 soft-delete
//  5. GET /v1/remotes/{rid} → 200 (still retrievable, removed_at_ns set)
//  6. GET /v1/verify?remote=...&tag=... → not_tracked or doesnt_exist
//  7. Store: AssertChainIntact (vacuous for chain_len=0)
func TestTracerRegisterAndVerify(t *testing.T) {
	s := testutil.NewTestStore(t)
	clk := &fixedClock{ns: 1_718_000_000_000_000_000}
	httpSrv := httptest.NewServer(NewServer(s, clk, nil))
	t.Cleanup(httpSrv.Close)

	ctx := context.Background()

	// --- 1. Create remote ---
	remoteBody := `{"url":"https://github.com/org/tracer-repo.git","transport":"https"}`
	resp, err := http.Post(httpSrv.URL+"/v1/remotes", "application/json", bytes.NewBufferString(remoteBody))
	if err != nil {
		t.Fatalf("POST /v1/remotes: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create remote: status = %d, want 201", resp.StatusCode)
	}
	var remoteJSON map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&remoteJSON) //nolint:errcheck
	_ = resp.Body.Close()
	rid := int64(remoteJSON["id"].(float64))
	if rid == 0 {
		t.Fatal("remote id must be non-zero")
	}

	// --- 2. Dup url → 409 ---
	resp2, _ := http.Post(httpSrv.URL+"/v1/remotes", "application/json", bytes.NewBufferString(remoteBody))
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("dup remote: status = %d, want 409", resp2.StatusCode)
	}

	// --- 3. List remotes → 1 item ---
	resp3, _ := http.Get(httpSrv.URL + "/v1/remotes")
	var listJSON map[string]any
	_ = json.NewDecoder(resp3.Body).Decode(&listJSON) //nolint:errcheck
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("list remotes: status = %d, want 200", resp3.StatusCode)
	}
	items := listJSON["items"].([]any)
	if len(items) != 1 {
		t.Errorf("list items = %d, want 1", len(items))
	}

	// --- 4. Soft-delete ---
	req4, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/remotes/%d", httpSrv.URL, rid), nil)
	resp4, _ := http.DefaultClient.Do(req4)
	_ = resp4.Body.Close()
	if resp4.StatusCode != http.StatusNoContent {
		t.Errorf("soft-delete: status = %d, want 204", resp4.StatusCode)
	}

	// --- 5. GET after soft-delete → 200, removed_at_ns set ---
	resp5, _ := http.Get(fmt.Sprintf("%s/v1/remotes/%d", httpSrv.URL, rid))
	var remoteAfter map[string]any
	_ = json.NewDecoder(resp5.Body).Decode(&remoteAfter) //nolint:errcheck
	_ = resp5.Body.Close()
	if resp5.StatusCode != http.StatusOK {
		t.Errorf("GET after soft-delete: status = %d, want 200", resp5.StatusCode)
	}
	if remoteAfter["removed_at_ns"] == nil {
		t.Errorf("removed_at_ns must be set after soft-delete")
	}

	// --- 6. Verify on deleted remote → doesnt_exist (we created it, just no tags) ---
	resp6, _ := http.Get(httpSrv.URL + "/v1/verify?remote=https://github.com/org/tracer-repo.git&tag=v1.0.0")
	var verifyJSON map[string]any
	_ = json.NewDecoder(resp6.Body).Decode(&verifyJSON) //nolint:errcheck
	_ = resp6.Body.Close()
	// The remote still exists (soft deleted but in store), so doesnt_exist for a non-existent tag.
	if verifyJSON["status"] != "doesnt_exist" && verifyJSON["status"] != "not_tracked" {
		t.Errorf("verify status = %v, want doesnt_exist or not_tracked", verifyJSON["status"])
	}

	// --- 7. AssertChainIntact (vacuous: chain_len=0) ---
	testutil.AssertChainIntact(t, ctx, s, model.RemoteID(rid))
}
