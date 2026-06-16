package sqlite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mivanov93/git-tainted/db"
	"github.com/mivanov93/git-tainted/internal/model"
)

func newTestStore(tb testing.TB) model.Store {
	tb.Helper()
	f, err := os.CreateTemp("", "git-tainted-test-*.db")
	if err != nil {
		tb.Fatalf("create temp db file: %v", err)
	}
	if err := f.Close(); err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = os.Remove(f.Name()) })

	// Open migrates from the embedded migration FS (no db/ folder needed).
	s, err := Open(f.Name(), db.SQLiteMigrations)
	if err != nil {
		tb.Fatalf("Open: %v", err)
	}
	tb.Cleanup(func() { _ = s.Close() })
	return s
}

// seedRemote inserts a minimal active remote for testing.
func seedRemote(tb testing.TB, s model.Store, url string) model.RemoteID {
	tb.Helper()
	id, err := s.CreateRemote(context.Background(), &model.Remote{
		URL:                 url,
		NormalizedURL:       url,
		Transport:           model.TransportHTTPS,
		TaintAnyTagDeletion: true,
		SyncInterval:        5 * time.Minute,
		StalenessBudget:     time.Hour,
		Status:              model.RemoteActive,
		ChainHeadHash:       make([]byte, 32),
		CreatedAtNS:         1_718_000_000_000_000_000,
		UpdatedAtNS:         1_718_000_000_000_000_000,
	})
	if err != nil {
		tb.Fatalf("seedRemote: %v", err)
	}
	return id
}

// ---- Remote CRUD ------------------------------------------------------------

func TestCreateAndGetRemote(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	r := &model.Remote{
		URL:                 "https://github.com/org/repo.git",
		NormalizedURL:       "https://github.com/org/repo.git",
		Transport:           model.TransportHTTPS,
		TaintAnyTagDeletion: true,
		SyncInterval:        5 * time.Minute,
		StalenessBudget:     time.Hour,
		Status:              model.RemoteActive,
		ChainHeadHash:       make([]byte, 32),
		CreatedAtNS:         1_718_000_000_000_000_000,
		UpdatedAtNS:         1_718_000_000_000_000_000,
	}
	id, err := s.CreateRemote(ctx, r)
	if err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}
	if id == 0 {
		t.Fatalf("zero id")
	}

	got, err := s.GetRemote(ctx, id)
	if err != nil {
		t.Fatalf("GetRemote: %v", err)
	}
	if got.NormalizedURL != r.NormalizedURL {
		t.Errorf("NormalizedURL = %q, want %q", got.NormalizedURL, r.NormalizedURL)
	}
	if got.Transport != model.TransportHTTPS {
		t.Errorf("Transport = %q, want https", got.Transport)
	}
	if len(got.ChainHeadHash) != 32 {
		t.Errorf("ChainHeadHash len = %d, want 32", len(got.ChainHeadHash))
	}
}

func TestGetRemoteByURL(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	url := "https://github.com/org/byurl.git"
	rid := seedRemote(t, s, url)

	got, err := s.GetRemoteByURL(ctx, url)
	if err != nil {
		t.Fatalf("GetRemoteByURL: %v", err)
	}
	if got.ID != rid {
		t.Errorf("ID = %d, want %d", got.ID, rid)
	}

	_, err = s.GetRemoteByURL(ctx, "https://no-such-remote.example.com/r.git")
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("missing remote: err = %v, want ErrNotFound", err)
	}
}

func TestCreateRemote_DupNormalizedURLConflict(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	r := &model.Remote{
		URL: "https://github.com/org/repo.git", NormalizedURL: "https://github.com/org/repo.git",
		Transport: model.TransportHTTPS, TaintAnyTagDeletion: true,
		SyncInterval: 5 * time.Minute, StalenessBudget: time.Hour,
		Status: model.RemoteActive, ChainHeadHash: make([]byte, 32),
		CreatedAtNS: 1_718_000_000_000_000_000, UpdatedAtNS: 1_718_000_000_000_000_000,
	}
	if _, err := s.CreateRemote(ctx, r); err != nil {
		t.Fatalf("first CreateRemote: %v", err)
	}
	_, err := s.CreateRemote(ctx, r)
	if !errors.Is(err, model.ErrConflict) {
		t.Fatalf("dup normalized_url: err = %v, want ErrConflict", err)
	}
}

func TestSoftDeleteRemote(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	rid := seedRemote(t, s, "https://github.com/org/del.git")

	atNS := int64(1_718_000_001_000_000_000)
	if err := s.SoftDeleteRemote(ctx, rid, atNS); err != nil {
		t.Fatalf("SoftDeleteRemote: %v", err)
	}

	// Remote is still retrievable (ledger + taint history retained).
	got, err := s.GetRemote(ctx, rid)
	if err != nil {
		t.Fatalf("GetRemote after soft-delete: %v", err)
	}
	if got.RemovedAtNS == nil {
		t.Errorf("RemovedAtNS must be set after soft-delete")
	}
	if *got.RemovedAtNS != atNS {
		t.Errorf("RemovedAtNS = %d, want %d", *got.RemovedAtNS, atNS)
	}
}

func TestListRemotes_Pagination(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for i := 0; i < 4; i++ {
		u := fmt.Sprintf("https://github.com/org/repo-%d.git", i)
		r := &model.Remote{
			URL: u, NormalizedURL: u,
			Transport: model.TransportHTTPS, TaintAnyTagDeletion: true,
			SyncInterval: 5 * time.Minute, StalenessBudget: time.Hour,
			Status: model.RemoteActive, ChainHeadHash: make([]byte, 32),
			CreatedAtNS: 1_718_000_000_000_000_000, UpdatedAtNS: 1_718_000_000_000_000_000,
		}
		if _, err := s.CreateRemote(ctx, r); err != nil {
			t.Fatalf("create remote %d: %v", i, err)
		}
	}

	page1, next1, err := s.ListRemotes(ctx, 2, 0)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("page1 len = %d, want 2", len(page1))
	}
	page2, _, err := s.ListRemotes(ctx, 2, next1)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("page2 len = %d, want 2", len(page2))
	}
}

// ---- Ref/tag CRUD -----------------------------------------------------------

func TestUpsertAndGetRef(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	rid := seedRemote(t, s, "https://github.com/org/refs.git")
	ref := &model.Ref{
		RemoteID:    rid,
		TagName:     "v1.0.0",
		CurrentOID:  model.MustParseOID("1111111111111111111111111111111111111111", model.SHA1),
		FirstSeenNS: 1_718_000_000_000_000_000,
		LastSeenNS:  1_718_000_000_000_000_000,
	}

	if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
		return tx.UpsertRefProjection(ctx, ref)
	}); err != nil {
		t.Fatalf("UpsertRefProjection: %v", err)
	}

	got, err := s.GetRef(ctx, rid, "v1.0.0")
	if err != nil {
		t.Fatalf("GetRef: %v", err)
	}
	if got.TagName != "v1.0.0" {
		t.Errorf("TagName = %q, want v1.0.0", got.TagName)
	}
	if !got.CurrentOID.Equal(ref.CurrentOID) {
		t.Errorf("CurrentOID = %s, want %s", got.CurrentOID.Hex(), ref.CurrentOID.Hex())
	}

	// GetRef for missing tag → ErrNotFound.
	_, err = s.GetRef(ctx, rid, "v99.99.99")
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("missing tag: err = %v, want ErrNotFound", err)
	}
}

func TestListTags(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	rid := seedRemote(t, s, "https://github.com/org/listtags.git")

	for _, name := range []string{"v1.0.0", "v1.1.0", "v2.0.0"} {
		ref := &model.Ref{RemoteID: rid, TagName: name}
		if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
			return tx.UpsertRefProjection(ctx, ref)
		}); err != nil {
			t.Fatalf("upsert %q: %v", name, err)
		}
	}

	tags, err := s.ListTags(ctx, rid)
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(tags) != 3 {
		t.Errorf("ListTags len = %d, want 3", len(tags))
	}
}

// ---- LatestObservationForRef -----------------------------------------------

func TestLatestObservationForRef(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	rid := seedRemote(t, s, "https://github.com/org/obsref.git")

	// Seed a ref.
	ref := &model.Ref{
		RemoteID:    rid,
		TagName:     "v1.0.0",
		CurrentOID:  model.MustParseOID("1111111111111111111111111111111111111111", model.SHA1),
		FirstSeenNS: 1_718_000_000_000_000_000,
		LastSeenNS:  1_718_000_000_000_000_000,
	}

	// ErrNotFound when no observations exist yet.
	if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
		return tx.UpsertRefProjection(ctx, ref)
	}); err != nil {
		t.Fatalf("UpsertRefProjection: %v", err)
	}
	_, err := s.LatestObservationForRef(ctx, ref.ID)
	if !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("empty ref: err=%v, want ErrNotFound", err)
	}

	// Append two observations. The second should be returned as latest.
	var seq1, seq2 model.Seq
	for i, hexOID := range []string{
		"1111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222",
	} {
		ev := model.EventTagOIDChanged
		if i == 0 {
			ev = model.EventTagCreated
		}
		if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
			if _, err := tx.WriteSync(ctx, &model.Sync{
				RemoteID: rid, Trigger: model.TriggerManual,
				StartedNS: int64(i + 1), FinishedNS: int64(i + 1),
				Status: model.SyncOk,
			}); err != nil {
				return err
			}
			o := &model.Observation{
				RemoteID:     rid,
				RefID:        ref.ID,
				EventType:    ev,
				NewOID:       model.MustParseOID(hexOID, model.SHA1),
				ObservedAtNS: int64(1_700_000_000_000_000_000 + i),
			}
			seq, err := tx.AppendObservation(ctx, o)
			if err != nil {
				return err
			}
			if i == 0 {
				seq1 = seq
			} else {
				seq2 = seq
			}
			return nil
		}); err != nil {
			t.Fatalf("append observation %d: %v", i, err)
		}
	}

	proof, err := s.LatestObservationForRef(ctx, ref.ID)
	if err != nil {
		t.Fatalf("LatestObservationForRef: %v", err)
	}
	if proof.Seq != seq2 {
		t.Errorf("Seq=%d want %d (latest)", proof.Seq, seq2)
	}
	if proof.Seq == seq1 {
		t.Errorf("got seq1=%d, want seq2=%d (highest)", seq1, seq2)
	}
	if len(proof.RowHash) != 32 {
		t.Errorf("RowHash len=%d want 32", len(proof.RowHash))
	}
	if proof.RemoteID != rid {
		t.Errorf("RemoteID=%d want %d", proof.RemoteID, rid)
	}
}

// ---- TaintEvent ------------------------------------------------------------

func TestAppendAndListTaintEvents(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	rid := seedRemote(t, s, "https://github.com/org/taint.git")

	// Need a ref.
	ref := &model.Ref{RemoteID: rid, TagName: "v1.0.0"}
	if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
		return tx.UpsertRefProjection(ctx, ref)
	}); err != nil {
		t.Fatalf("upsert ref: %v", err)
	}
	got, _ := s.GetRef(ctx, rid, "v1.0.0")

	te := &model.TaintEvent{
		RemoteID:     rid,
		RefID:        got.ID,
		Reason:       model.TaintTagOIDChanged,
		DetectedAtNS: 1_718_000_000_000_000_001,
	}
	var evID int64
	if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
		var err error
		evID, err = tx.AppendTaintEvent(ctx, te)
		return err
	}); err != nil {
		t.Fatalf("AppendTaintEvent: %v", err)
	}
	if evID == 0 {
		t.Fatal("taint event id must be non-zero")
	}

	events, next, err := s.ListTaintEvents(ctx, rid, 10, 0)
	if err != nil {
		t.Fatalf("ListTaintEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	_ = next

	// Ack it.
	if err := s.AckTaintEvent(ctx, evID, "operator", "reviewed", 1_718_000_000_000_000_002); err != nil {
		t.Fatalf("AckTaintEvent: %v", err)
	}
}

// ---- Syncs -----------------------------------------------------------------

func TestWriteAndListSyncs(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	rid := seedRemote(t, s, "https://github.com/org/syncs.git")

	sy := &model.Sync{
		RemoteID:    rid,
		Trigger:     model.TriggerManual,
		StartedNS:   1_718_000_000_000_000_000,
		FinishedNS:  1_718_000_000_001_000_000,
		Status:      model.SyncOk,
		TagsSeen:    5,
		TagsChanged: 1,
	}
	if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
		_, err := tx.WriteSync(ctx, sy)
		return err
	}); err != nil {
		t.Fatalf("WriteSync: %v", err)
	}

	syncs, _, err := s.ListSyncs(ctx, rid, 10, 0)
	if err != nil {
		t.Fatalf("ListSyncs: %v", err)
	}
	if len(syncs) != 1 {
		t.Fatalf("syncs len = %d, want 1", len(syncs))
	}
	if syncs[0].TagsSeen != 5 {
		t.Errorf("TagsSeen = %d, want 5", syncs[0].TagsSeen)
	}
}
