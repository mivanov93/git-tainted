package sync_test

import (
	"context"
	"testing"
	"time"

	"github.com/mivanov93/git-tainted/internal/git"
	"github.com/mivanov93/git-tainted/internal/lock"
	"github.com/mivanov93/git-tainted/internal/model"
	tlsync "github.com/mivanov93/git-tainted/internal/sync"
	"github.com/mivanov93/git-tainted/internal/testutil"
)

// TestSyncRemote_Retention verifies sync-audit retention: every sync prunes the
// table down to the newest few rows per remote, EXCEPT syncs still referenced by
// a ledger observation (FK-pinned), which must survive however old they get.
func TestSyncRemote_Retention(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewTestStore(t)
	clk := testutil.NewFakeClock(1_700_000_000_000_000_000)
	srv := testutil.StartGitServer(t)

	const base = 1_700_000_000_000_000_000
	b := testutil.NewRepo(t, srv, "repo.git", model.SHA1)
	b.Commit("main", "c1", nil, base, base)
	b.LightweightTag("v1.0", "c1")
	b.AnnotatedTag("v2.0", "c1", "rel", base+1)

	rid, err := s.CreateRemote(ctx, &model.Remote{
		URL:                 srv.URL("repo.git"),
		NormalizedURL:       srv.URL("repo.git"),
		Transport:           model.TransportHTTPS,
		Status:              model.RemoteActive,
		TaintAnyTagDeletion: true,
		ChainHeadHash:       make([]byte, 32),
		CreatedAtNS:         clk.NowNS(),
		UpdatedAtNS:         clk.NowNS(),
	})
	if err != nil {
		t.Fatal(err)
	}

	syncer := tlsync.NewRemoteSyncer(s, git.NewRunnerWithProtocols("git", 30*time.Second, "http:https:ssh"), lock.NewDBLease(s, clk), clk, "inst-test")

	// First sync records the two tag_created observations (FK-pins sync #1); the
	// next nine see no changes → no observations → prunable.
	const total = 10
	for i := 0; i < total; i++ {
		if _, err := syncer.SyncRemote(ctx, rid); err != nil {
			t.Fatalf("sync %d: %v", i, err)
		}
	}

	syncs, _, err := s.ListSyncs(ctx, rid, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Newest 5 + the 1 FK-pinned change-sync = 6 rows; the rest were pruned.
	if len(syncs) != 6 {
		ids := make([]int64, len(syncs))
		for i, sy := range syncs {
			ids[i] = int64(sy.ID)
		}
		t.Fatalf("retention: got %d syncs %v, want 6 (newest 5 + 1 FK-pinned)", len(syncs), ids)
	}
	// The oldest survivor is the FK-pinned first sync (id 1) — kept despite being
	// far older than the newest 5.
	if oldest := syncs[len(syncs)-1]; int64(oldest.ID) != 1 {
		t.Errorf("oldest retained sync id=%d, want 1 (FK-pinned)", int64(oldest.ID))
	}

	// Pagination: keyset-walk every row with a tiny page size; must terminate and
	// return each row once (cursor flows newest→oldest via id < cursor, no phantom
	// cursor on the last page).
	var paged []int64
	for cursor := int64(0); ; {
		page, next, err := s.ListSyncs(ctx, rid, 2, cursor)
		if err != nil {
			t.Fatal(err)
		}
		for _, sy := range page {
			paged = append(paged, int64(sy.ID))
		}
		if next == 0 {
			break
		}
		cursor = next
		if len(paged) > 50 {
			t.Fatal("pagination did not terminate (cursor bug)")
		}
	}
	if len(paged) != 6 {
		t.Errorf("paged %d rows %v across pages, want 6", len(paged), paged)
	}
}
