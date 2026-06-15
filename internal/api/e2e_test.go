//go:build e2e

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mivanov93/git-tainted/internal/api"
	"github.com/mivanov93/git-tainted/internal/git"
	"github.com/mivanov93/git-tainted/internal/lock"
	"github.com/mivanov93/git-tainted/internal/model"
	tlsync "github.com/mivanov93/git-tainted/internal/sync"
	"github.com/mivanov93/git-tainted/internal/testutil"
)

// newE2EServer returns a full httptest.Server backed by a real SQLite store,
// real RemoteSyncer, and the complete HTTP handler stack.
func newE2EServer(tb testing.TB) (*httptest.Server, model.Store, *testutil.FakeClock, *tlsync.RemoteSyncer) {
	tb.Helper()

	s := testutil.NewTestStore(tb)
	clk := testutil.NewFakeClock(1_700_000_000_000_000_000)

	// Allow http:// for the loopback git fixture server (the protocol allowlist
	// controls which git transport protocols the git runner accepts).
	runner := git.NewRunnerWithProtocols("git", 30_000_000_000, "http:https:ssh")
	lk := lock.NewDBLease(s, clk)
	syncer := tlsync.NewRemoteSyncer(s, runner, lk, clk, "e2e-test")

	handler := api.NewServer(s, clk, syncer)
	srv := httptest.NewServer(handler)
	tb.Cleanup(srv.Close)
	return srv, s, clk, syncer
}

// decodeJSON reads the response body into out; caller must close the body.
func decodeJSON(tb testing.TB, resp *http.Response, out any) {
	tb.Helper()
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		tb.Fatalf("decodeJSON: %v", err)
	}
}

// seedFixtureRemote inserts a remote directly in the store (bypassing the HTTP
// URL-scheme validation which rejects plain http:// fixture URLs). All other
// assertions use the real HTTP handler.
func seedFixtureRemote(tb testing.TB, ctx context.Context, s model.Store, clk *testutil.FakeClock, rawURL string) model.RemoteID {
	tb.Helper()
	rid, err := s.CreateRemote(ctx, &model.Remote{
		URL:                 rawURL,
		NormalizedURL:       rawURL,
		Transport:           model.TransportHTTPS,
		SyncIntervalNS:      300_000_000_000,
		StalenessBudgetNS:   3_600_000_000_000,
		TaintAnyTagDeletion: true,
		Status:              model.RemoteActive,
		ChainHeadHash:       make([]byte, 32),
		CreatedAtNS:         clk.NowNS(),
		UpdatedAtNS:         clk.NowNS(),
	})
	if err != nil {
		tb.Fatalf("seedFixtureRemote: %v", err)
	}
	return rid
}

// TestE2E_FullSyncAndVerify is the primary end-to-end proof:
//
//  1. Register a remote pointing at a fixture repo (lightweight + annotated tag).
//  2. Run a sync via syncer.SyncRemote.
//  3. Verify via GET /v1/verify:
//     - known tag → "ok"
//     - wrong commit → "mismatch"
//     - unknown tag → "doesnt_exist"
//     - unregistered remote → "not_tracked"
//  4. Move the annotated tag to a different commit, re-sync.
//  5. Assert GET /v1/verify → "tainted" + a tag_oid_changed taint event in
//     GET /v1/remotes/{id}/taint-events.
//  6. AssertChainIntact.
func TestE2E_FullSyncAndVerify(t *testing.T) {
	ctx := context.Background()
	srv, s, clk, syncer := newE2EServer(t)

	// ── Build a fixture git repo ──────────────────────────────────────────────
	gitSrv := testutil.StartGitServer(t)
	const base = 1_700_000_000_000_000_000
	repo := testutil.NewRepo(t, gitSrv, "e2e-repo.git", model.SHA1)
	c1 := repo.Commit("main", "c1", nil, base, base)
	c2 := repo.Commit("main", "c2", []string{"c1"}, base+1, base+1)

	lwOID := repo.LightweightTag("v1.0", "c1") // lightweight tag → commit c1
	annOID := repo.AnnotatedTag("v2.0", "c2", "release", base+2)

	t.Logf("c1=%s c2=%s v1.0(lw)=%s v2.0(ann)=%s",
		c1.Hex(), c2.Hex(), lwOID.Hex(), annOID.Hex())

	repoURL := gitSrv.URL("e2e-repo.git")

	// ── 1. Register the remote (store-level, http:// fixture bypasses URL check) ─
	rid := seedFixtureRemote(t, ctx, s, clk, repoURL)
	t.Logf("registered remote id=%d url=%s", rid, repoURL)

	// Confirm GET /v1/remotes/{id} returns the remote.
	resp, err := http.Get(fmt.Sprintf("%s/v1/remotes/%d", srv.URL, rid))
	if err != nil {
		t.Fatalf("GET /v1/remotes/%d: %v", rid, err)
	}
	var remoteJSON map[string]any
	decodeJSON(t, resp, &remoteJSON)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/remotes/%d: status=%d, want 200", rid, resp.StatusCode)
	}

	// ── 2. Sync ───────────────────────────────────────────────────────────────
	if _, err := syncer.SyncRemote(ctx, rid); err != nil {
		t.Fatalf("SyncRemote: %v", err)
	}

	// Confirm tags landed via GET /v1/remotes/{id}/tags.
	resp2, err := http.Get(fmt.Sprintf("%s/v1/remotes/%d/tags", srv.URL, rid))
	if err != nil {
		t.Fatalf("GET /v1/remotes/%d/tags: %v", rid, err)
	}
	var tagList map[string]any
	decodeJSON(t, resp2, &tagList)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/remotes/%d/tags: status=%d", rid, resp2.StatusCode)
	}
	tags := tagList["items"].([]any)
	if len(tags) != 2 {
		t.Fatalf("expected 2 tags after sync, got %d", len(tags))
	}
	t.Logf("tags after sync: %d ✓", len(tags))

	// ── 3a. Verify known tag → "ok" ──────────────────────────────────────────
	resp3a, err := http.Get(fmt.Sprintf("%s/v1/verify?remote=%s&tag=v1.0", srv.URL, repoURL))
	if err != nil {
		t.Fatalf("verify v1.0: %v", err)
	}
	var vOK map[string]any
	decodeJSON(t, resp3a, &vOK)
	if resp3a.StatusCode != http.StatusOK {
		t.Fatalf("verify v1.0: status=%d", resp3a.StatusCode)
	}
	if vOK["status"] != "ok" {
		t.Errorf("verify v1.0 status=%v, want ok; full: %v", vOK["status"], vOK)
	} else {
		t.Log("verify v1.0 → ok ✓")
	}

	// ── 3a-lw. lightweight tag peeled_commit_oid must equal the commit ────────
	// After the projectTag fix, peeled_commit_oid is populated for lightweight
	// tags (= CurrentOID) so clients always get the checkout-commit directly.
	if rec, ok := vOK["recorded"].(map[string]any); ok {
		pco, hasPCO := rec["peeled_commit_oid"].(string)
		if !hasPCO || pco == "" {
			t.Errorf("lightweight tag v1.0 verify response missing peeled_commit_oid; recorded=%v", rec)
		} else if pco != lwOID.Hex() {
			t.Errorf("lightweight tag v1.0 peeled_commit_oid=%s want %s", pco, lwOID.Hex())
		} else {
			t.Logf("lightweight tag v1.0 peeled_commit_oid=%s ✓", pco)
		}
	} else {
		t.Errorf("verify v1.0 response missing 'recorded' field; full: %v", vOK)
	}

	// ── 3a-lp. ok verify must have non-nil ledger_proof with RowHash + Seq≥1 ─
	if lp, ok2 := vOK["ledger_proof"].(map[string]any); !ok2 || lp == nil {
		t.Errorf("verify v1.0 ok: ledger_proof missing or nil; full: %v", vOK)
	} else {
		rh, hasRH := lp["row_hash"].(string)
		sq, hasSQ := lp["seq"].(float64)
		if !hasRH || rh == "" {
			t.Errorf("ledger_proof.row_hash missing or empty; ledger_proof=%v", lp)
		}
		if !hasSQ || sq < 1 {
			t.Errorf("ledger_proof.seq=%v want ≥1; ledger_proof=%v", sq, lp)
		}
		t.Logf("ledger_proof: seq=%v row_hash=%s ✓", sq, rh)
	}

	// ── 3b. Verify with wrong commit → "mismatch" ─────────────────────────────
	wrongCommit := "0000000000000000000000000000000000000001"
	resp3b, err := http.Get(fmt.Sprintf("%s/v1/verify?remote=%s&tag=v1.0&commit=%s",
		srv.URL, repoURL, wrongCommit))
	if err != nil {
		t.Fatalf("verify v1.0 wrong commit: %v", err)
	}
	var vMismatch map[string]any
	decodeJSON(t, resp3b, &vMismatch)
	if vMismatch["status"] != "mismatch" {
		t.Errorf("verify v1.0 wrong commit: status=%v, want mismatch", vMismatch["status"])
	} else {
		t.Log("verify v1.0 wrong commit → mismatch ✓")
	}

	// ── 3c. Verify unknown tag → "doesnt_exist" ───────────────────────────────
	resp3c, err := http.Get(fmt.Sprintf("%s/v1/verify?remote=%s&tag=v99.0", srv.URL, repoURL))
	if err != nil {
		t.Fatalf("verify v99.0: %v", err)
	}
	var vNotExist map[string]any
	decodeJSON(t, resp3c, &vNotExist)
	if vNotExist["status"] != "doesnt_exist" {
		t.Errorf("verify v99.0: status=%v, want doesnt_exist", vNotExist["status"])
	} else {
		t.Log("verify v99.0 → doesnt_exist ✓")
	}
	if _, hasLP := vNotExist["ledger_proof"]; hasLP {
		t.Errorf("doesnt_exist response must not have ledger_proof; full: %v", vNotExist)
	}

	// ── 3d. Verify unregistered remote → "not_tracked" ────────────────────────
	resp3d, err := http.Get(fmt.Sprintf(
		"%s/v1/verify?remote=https://github.com/unknown/repo.git&tag=v1.0", srv.URL))
	if err != nil {
		t.Fatalf("verify unknown remote: %v", err)
	}
	var vNotTracked map[string]any
	decodeJSON(t, resp3d, &vNotTracked)
	if vNotTracked["status"] != "not_tracked" {
		t.Errorf("verify unknown remote: status=%v, want not_tracked", vNotTracked["status"])
	} else {
		t.Log("verify unknown remote → not_tracked ✓")
	}
	if _, hasLP := vNotTracked["ledger_proof"]; hasLP {
		t.Errorf("not_tracked response must not have ledger_proof; full: %v", vNotTracked)
	}

	// ── 4. Move annotated tag to a different commit, re-sync ──────────────────
	c3 := repo.Commit("main", "c3", []string{"c2"}, base+3, base+3)
	newAnnOID := repo.AnnotatedTag("v2.0", "c3", "force-moved", base+4)
	t.Logf("c3=%s new v2.0(ann)=%s", c3.Hex(), newAnnOID.Hex())

	// Advance fake clock so the second sync has a strictly-later timestamp.
	clk.Advance(1_000_000_000) // +1s
	time.Sleep(time.Millisecond) // ensure wall-time ordering too

	if _, err := syncer.SyncRemote(ctx, rid); err != nil {
		t.Fatalf("second SyncRemote: %v", err)
	}

	// ── 5a. GET /v1/verify → "tainted" ────────────────────────────────────────
	resp5a, err := http.Get(fmt.Sprintf("%s/v1/verify?remote=%s&tag=v2.0", srv.URL, repoURL))
	if err != nil {
		t.Fatalf("verify v2.0 after retag: %v", err)
	}
	var vTainted map[string]any
	decodeJSON(t, resp5a, &vTainted)
	if vTainted["status"] != "tainted" {
		t.Errorf("verify v2.0 after retag: status=%v, want tainted", vTainted["status"])
	} else {
		t.Log("verify v2.0 after force-move → tainted ✓")
	}

	// ── 5b. GET /v1/remotes/{id}/taint-events → tag_oid_changed event ─────────
	resp5b, err := http.Get(fmt.Sprintf("%s/v1/remotes/%d/taint-events", srv.URL, rid))
	if err != nil {
		t.Fatalf("GET taint-events: %v", err)
	}
	var taintList map[string]any
	decodeJSON(t, resp5b, &taintList)
	if resp5b.StatusCode != http.StatusOK {
		t.Fatalf("GET taint-events: status=%d", resp5b.StatusCode)
	}
	taintItems := taintList["items"].([]any)
	if len(taintItems) == 0 {
		t.Fatal("expected at least one taint event")
	}
	firstEvent := taintItems[0].(map[string]any)
	if firstEvent["reason"] != "tag_oid_changed" {
		t.Errorf("taint reason=%v, want tag_oid_changed", firstEvent["reason"])
	} else {
		t.Logf("taint event reason=tag_oid_changed ✓")
	}

	// ── 6. AssertChainIntact ──────────────────────────────────────────────────
	testutil.AssertChainIntact(t, ctx, s, rid)
	t.Log("chain intact ✓")
}

// TestE2E_TriggerSyncEndpoint verifies the POST /v1/remotes/{id}/sync endpoint
// is wired and returns 202 for existing remotes, 404 for unknown.
func TestE2E_TriggerSyncEndpoint(t *testing.T) {
	ctx := context.Background()
	srv, s, clk, _ := newE2EServer(t)

	// Register a remote via POST /v1/remotes (https URL is valid).
	var remoteJSON map[string]any
	resp, err := http.Post(
		srv.URL+"/v1/remotes",
		"application/json",
		bytes.NewBufferString(`{"url":"https://github.com/org/testrepo.git","transport":"https"}`))
	if err != nil {
		t.Fatalf("POST /v1/remotes: %v", err)
	}
	decodeJSON(t, resp, &remoteJSON)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create remote: status=%d, want 201", resp.StatusCode)
	}
	rid := int64(remoteJSON["id"].(float64))
	t.Logf("registered remote id=%d", rid)
	_ = ctx
	_ = s
	_ = clk

	// POST /sync → 202.
	resp2, err := http.Post(
		fmt.Sprintf("%s/v1/remotes/%d/sync", srv.URL, rid),
		"application/json", nil)
	if err != nil {
		t.Fatalf("POST /sync: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusAccepted {
		t.Errorf("POST /sync: status=%d, want 202", resp2.StatusCode)
	} else {
		t.Log("POST /sync → 202 ✓")
	}

	// POST /sync on unknown remote → 404.
	resp3, err := http.Post(
		fmt.Sprintf("%s/v1/remotes/99999/sync", srv.URL),
		"application/json", nil)
	if err != nil {
		t.Fatalf("POST /sync unknown: %v", err)
	}
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Errorf("POST /sync unknown: status=%d, want 404", resp3.StatusCode)
	} else {
		t.Log("POST /sync unknown remote → 404 ✓")
	}
}
