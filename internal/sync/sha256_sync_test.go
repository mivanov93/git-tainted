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

// TestSyncRemote_SHA256_NoFalseTaintOnResync is the end-to-end regression for the
// sha256 oid-decode bug (fix 17fc588). A sha256 remote, synced twice with NO
// change to the repo, must NOT taint its tags.
//
// Before the fix the store decoded the stored sha256 oid as sha1, so the second
// sync's ClassifyTag evaluated now.OID(sha256).Equal(prev.CurrentOID(sha1)) ==
// false → a spurious tag_oid_changed taint on every unchanged sha256 tag. This
// was never caught because the git-server testutil only made sha1 repos; it now
// honors --object-format, so this exercises the real sha256 path.
func TestSyncRemote_SHA256_NoFalseTaintOnResync(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewTestStore(t)
	clk := testutil.NewFakeClock(1_700_000_000_000_000_000)
	srv := testutil.StartGitServer(t)

	const base = 1_700_000_000_000_000_000
	b := testutil.NewRepo(t, srv, "sha256repo.git", model.SHA256)
	b.Commit("main", "c1", nil, base, base)
	b.LightweightTag("v1.0", "c1")
	b.AnnotatedTag("v2.0", "c1", "rel", base+1)

	rid, err := s.CreateRemote(ctx, &model.Remote{
		URL:                 srv.URL("sha256repo.git"),
		NormalizedURL:       srv.URL("sha256repo.git"),
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
	syncer := tlsync.NewRemoteSyncer(s, git.NewRunnerWithProtocols("git", 30*time.Second, "http:https:ssh"), lock.NewDBLease(s, clk), clk, "inst-sha256")

	// First sync establishes the sha256 baseline.
	if _, err := syncer.SyncRemote(ctx, rid); err != nil {
		t.Fatalf("first SyncRemote: %v", err)
	}

	// Sanity: the stored oids must actually be sha256 — proves the testutil
	// honored --object-format=sha256 (else this test would silently retest sha1).
	tag, err := s.GetRef(ctx, rid, "v1.0")
	if err != nil {
		t.Fatalf("GetRef v1.0: %v", err)
	}
	if tag.CurrentOID.Algo != model.SHA256 {
		t.Fatalf("expected a sha256 repo; CurrentOID.Algo=%q (testutil did not produce sha256 oids)", tag.CurrentOID.Algo)
	}
	if tag.Tainted {
		t.Fatal("tag tainted after the FIRST sync — should be a clean baseline")
	}

	// Second sync, repo UNCHANGED → must be a no-op, never a taint.
	res2, err := syncer.SyncRemote(ctx, rid)
	if err != nil {
		t.Fatalf("second SyncRemote: %v", err)
	}
	if res2.TagsChanged != 0 {
		t.Errorf("second sync tags_changed=%d, want 0 (unchanged sha256 tags must not re-taint)", res2.TagsChanged)
	}
	for _, name := range []string{"v1.0", "v2.0"} {
		ref, err := s.GetRef(ctx, rid, name)
		if err != nil {
			t.Fatalf("GetRef %s: %v", name, err)
		}
		if ref.Tainted {
			t.Errorf("tag %s falsely tainted on re-sync of an UNCHANGED sha256 repo (the C2 bug)", name)
		}
	}

	// No new observations on the no-op second sync: the chain stays at 2 (one
	// tag_created per tag). False taints would have appended tag_oid_changed rows.
	if _, length, err := s.GetChainHead(ctx, rid); err != nil {
		t.Fatal(err)
	} else if length != 2 {
		t.Errorf("chain_len=%d after a no-op re-sync, want 2 (a false taint would append observations)", length)
	}
	testutil.AssertChainIntact(t, ctx, s, rid)
}
