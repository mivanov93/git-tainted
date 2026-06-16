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

func TestSyncRemote_RecordsTagsAndChain(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewTestStore(t)
	clk := testutil.NewFakeClock(1_700_000_000_000_000_000)
	srv := testutil.StartGitServer(t)

	const base = 1_700_000_000_000_000_000
	b := testutil.NewRepo(t, srv, "repo.git", model.SHA1)
	c1 := b.Commit("main", "c1", nil, base, base)
	lwOID := b.LightweightTag("v1.0", "c1") // returns commit OID for a lightweight tag
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

	res, err := syncer.SyncRemote(ctx, rid)
	if err != nil {
		t.Fatalf("SyncRemote: %v", err)
	}
	if res.TagsSeen != 2 {
		t.Errorf("tags_seen=%d want 2", res.TagsSeen)
	}
	if res.Status != model.SyncOk {
		t.Errorf("status=%q want ok", res.Status)
	}

	// projection: 2 tags present
	tags, err := s.ListTags(ctx, rid)
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(tags) != 2 {
		t.Errorf("got %d tags, want 2", len(tags))
	}

	// Check annotated tag has peeled oid
	tagAnn, err := s.GetRef(ctx, rid, "v2.0")
	if err != nil || !tagAnn.IsAnnotatedTag || tagAnn.CurrentPeeledOID.IsZero() {
		t.Fatalf("annotated tag projection wrong: %v %+v", err, tagAnn)
	}

	// Lightweight tag: CurrentPeeledOID must equal CurrentOID (the commit).
	// Before the fix both were zero for lightweight tags; now the projection
	// fills CurrentPeeledOID with the commit the tag points at.
	tagLW, err := s.GetRef(ctx, rid, "v1.0")
	if err != nil {
		t.Fatalf("GetRef v1.0: %v", err)
	}
	if tagLW.CurrentPeeledOID.IsZero() {
		t.Error("lightweight tag CurrentPeeledOID must not be zero after projection")
	}
	if !tagLW.CurrentPeeledOID.Equal(tagLW.CurrentOID) {
		t.Errorf("lightweight tag CurrentPeeledOID=%s want CurrentOID=%s",
			tagLW.CurrentPeeledOID.Hex(), tagLW.CurrentOID.Hex())
	}
	// Also confirm it equals the commit OID returned by the builder.
	if !tagLW.CurrentPeeledOID.Equal(lwOID) {
		t.Errorf("lightweight tag CurrentPeeledOID=%s want c1=%s",
			tagLW.CurrentPeeledOID.Hex(), lwOID.Hex())
	}
	_ = c1 // same as lwOID for a lightweight tag; kept for doc clarity

	// chain advanced by 2 (one tag_created per tag)
	_, length, err := s.GetChainHead(ctx, rid)
	if err != nil {
		t.Fatal(err)
	}
	if length != 2 {
		t.Errorf("chain_len=%d want 2", length)
	}
	testutil.AssertChainIntact(t, ctx, s, rid)
}

func TestSyncRemote_TaintsOnOIDChange(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewTestStore(t)
	clk := testutil.NewFakeClock(1_700_000_000_000_000_000)
	srv := testutil.StartGitServer(t)

	const base = 1_700_000_000_000_000_000
	b := testutil.NewRepo(t, srv, "repo.git", model.SHA1)
	b.Commit("main", "c1", nil, base, base)
	b.LightweightTag("v1.0", "c1")

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

	// First sync: tag created.
	if _, err := syncer.SyncRemote(ctx, rid); err != nil {
		t.Fatalf("first SyncRemote: %v", err)
	}

	// Move the tag to a new commit (simulates force-push).
	b.Commit("main", "c2", []string{"c1"}, base+2, base+2)
	b.LightweightTag("v1.0", "c2")

	// Second sync: tag oid changed → tainted.
	if _, err := syncer.SyncRemote(ctx, rid); err != nil {
		t.Fatalf("second SyncRemote: %v", err)
	}

	ref, err := s.GetRef(ctx, rid, "v1.0")
	if err != nil {
		t.Fatal(err)
	}
	if !ref.Tainted {
		t.Error("tag must be tainted after oid change")
	}

	events, _, err := s.ListTaintEvents(ctx, rid, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Error("expected at least one taint_event")
	}
	if events[0].Reason != model.TaintTagOIDChanged {
		t.Errorf("taint reason=%q want tag_oid_changed", events[0].Reason)
	}

	testutil.AssertChainIntact(t, ctx, s, rid)
}
