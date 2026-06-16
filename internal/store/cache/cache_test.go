package cache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
)

// ---- call-counting fake inner store ----------------------------------------

// fakeStore is a minimal in-memory model.Store used to assert the decorator's
// behavior. It counts every cached-read call so a test can prove a value was
// served from the Otter cache (inner not re-hit) vs. re-fetched (inner hit
// again after an invalidation). Backing state is mutable under mu so writes are
// observable by subsequent reads — essential for the correctness/race test.
type fakeStore struct {
	mu sync.Mutex

	// per-method call counters (atomic so the race test can read them safely).
	getRemoteN   atomic.Int64
	getByURLN    atomic.Int64
	getRefN      atomic.Int64
	listTagsN    atomic.Int64
	lobsN        atomic.Int64
	withTxN      atomic.Int64
	createN      atomic.Int64
	updateN      atomic.Int64
	softDeleteN  atomic.Int64
	setHealthN   atomic.Int64
	setRefTaintN atomic.Int64

	// backing state (guarded by mu).
	remotes map[model.RemoteID]*model.Remote
	byURL   map[string]model.RemoteID
	// refs keyed by (remoteID,tag); refVer is a per-refID monotonically-increasing
	// version written inside WithTx, the "freshness" the race test asserts on.
	refs   map[refKey]*model.Ref
	refVer map[model.RefID]int64
	// proof per refID (its RemoteID + a Seq mirroring refVer).
	proofs map[model.RefID]*model.ObservationProof

	// failTx, when set, makes WithTx return this error (rollback path test).
	failTx error
	// failNextWrite, when set, makes the next single-shot write return it.
	failWrite error
}

type refKey struct {
	remoteID model.RemoteID
	tag      string
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		remotes: map[model.RemoteID]*model.Remote{},
		byURL:   map[string]model.RemoteID{},
		refs:    map[refKey]*model.Ref{},
		refVer:  map[model.RefID]int64{},
		proofs:  map[model.RefID]*model.ObservationProof{},
	}
}

// seed adds a remote with one ref/proof so reads have something to return.
func (f *fakeStore) seed(remoteID model.RemoteID, normURL string, refID model.RefID, tag string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.remotes[remoteID] = &model.Remote{ID: remoteID, NormalizedURL: normURL, Status: model.RemoteActive}
	f.byURL[normURL] = remoteID
	f.refs[refKey{remoteID, tag}] = &model.Ref{ID: refID, RemoteID: remoteID, TagName: tag}
	f.refVer[refID] = 0
	f.proofs[refID] = &model.ObservationProof{RemoteID: remoteID, Seq: 0}
}

// ---- cached reads (counted) ----

func (f *fakeStore) GetRemote(_ context.Context, id model.RemoteID) (*model.Remote, error) {
	f.getRemoteN.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.remotes[id]
	if !ok {
		return nil, model.ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (f *fakeStore) GetRemoteByURL(_ context.Context, normalizedURL string) (*model.Remote, error) {
	f.getByURLN.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.byURL[normalizedURL]
	if !ok {
		return nil, model.ErrNotFound
	}
	r, ok := f.remotes[id]
	if !ok { // soft-deleted: index entry lingered but the remote is gone
		return nil, model.ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (f *fakeStore) GetRef(_ context.Context, remoteID model.RemoteID, tagName string) (*model.Ref, error) {
	f.getRefN.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.refs[refKey{remoteID, tagName}]
	if !ok {
		return nil, model.ErrNotFound
	}
	cp := *r
	cp.ObservationCount = f.refVer[r.ID] // expose the current version via a field
	return &cp, nil
}

func (f *fakeStore) ListTags(_ context.Context, remoteID model.RemoteID) ([]model.Ref, error) {
	f.listTagsN.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []model.Ref
	for k, r := range f.refs {
		if k.remoteID == remoteID {
			cp := *r
			cp.ObservationCount = f.refVer[r.ID]
			out = append(out, cp)
		}
	}
	return out, nil
}

func (f *fakeStore) LatestObservationForRef(_ context.Context, refID model.RefID) (*model.ObservationProof, error) {
	f.lobsN.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.proofs[refID]
	if !ok {
		return nil, model.ErrNotFound
	}
	cp := *p
	cp.Seq = model.Seq(f.refVer[refID]) // Seq mirrors the version
	return &cp, nil
}

// ---- invalidating writes (counted, mutate backing state) ----

func (f *fakeStore) CreateRemote(_ context.Context, r *model.Remote) (model.RemoteID, error) {
	f.createN.Add(1)
	if f.failWrite != nil {
		err := f.failWrite
		f.failWrite = nil
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.remotes[r.ID] = r
	f.byURL[r.NormalizedURL] = r.ID
	return r.ID, nil
}

func (f *fakeStore) UpdateRemote(_ context.Context, r *model.Remote) error {
	f.updateN.Add(1)
	if f.failWrite != nil {
		err := f.failWrite
		f.failWrite = nil
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.remotes[r.ID] = r
	return nil
}

func (f *fakeStore) SoftDeleteRemote(_ context.Context, id model.RemoteID, _ int64) error {
	f.softDeleteN.Add(1)
	if f.failWrite != nil {
		err := f.failWrite
		f.failWrite = nil
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.remotes[id]; ok {
		delete(f.byURL, r.NormalizedURL)
	}
	delete(f.remotes, id)
	return nil
}

func (f *fakeStore) SetRemoteHealth(_ context.Context, id model.RemoteID, status model.RemoteStatus, _ string, lastOkNS int64) error {
	f.setHealthN.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.remotes[id]; ok {
		r.Status = status
		r.LastOkNS = lastOkNS
	}
	return nil
}

func (f *fakeStore) SetRefTaint(_ context.Context, refID model.RefID, _ int64) error {
	f.setRefTaintN.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refVer[refID]++
	return nil
}

// ---- WithTx ----

func (f *fakeStore) WithTx(ctx context.Context, fn func(ctx context.Context, tx model.Tx) error) error {
	f.withTxN.Add(1)
	tx := &fakeTx{f: f}
	if err := fn(ctx, tx); err != nil {
		return err // user error → rollback
	}
	if f.failTx != nil {
		return f.failTx // simulated commit failure → rollback
	}
	// commit: apply recorded ref-version bumps atomically.
	f.mu.Lock()
	defer f.mu.Unlock()
	for refID := range tx.bumpRefs {
		f.refVer[refID]++
		if p, ok := f.proofs[refID]; ok {
			p.Seq = model.Seq(f.refVer[refID])
		}
	}
	return nil
}

// fakeTx records the refIDs an in-flight transaction touches and applies their
// version bump on commit (see WithTx).
type fakeTx struct {
	f        *fakeStore
	bumpRefs map[model.RefID]struct{}
}

func (t *fakeTx) markRef(refID model.RefID) {
	if t.bumpRefs == nil {
		t.bumpRefs = map[model.RefID]struct{}{}
	}
	t.bumpRefs[refID] = struct{}{}
}

func (t *fakeTx) AppendObservation(_ context.Context, o *model.Observation) (model.Seq, error) {
	t.markRef(o.RefID)
	return 0, nil
}
func (t *fakeTx) UpsertRefProjection(_ context.Context, ref *model.Ref) error {
	t.markRef(ref.ID)
	return nil
}
func (t *fakeTx) WriteSync(_ context.Context, _ *model.Sync) (model.SyncID, error) { return 0, nil }
func (t *fakeTx) AdvanceChainHead(_ context.Context, _ model.RemoteID, _ []byte, _ int64) error {
	return nil
}
func (t *fakeTx) AppendTaintEvent(_ context.Context, e *model.TaintEvent) (int64, error) {
	t.markRef(e.RefID)
	return 0, nil
}

// ---- unhit pass-through methods (satisfy model.Store) ----

func (f *fakeStore) ListRemotes(context.Context, int, int64) ([]model.Remote, int64, error) {
	return nil, 0, nil
}
func (f *fakeStore) SelectDueRemotes(context.Context, int64, int) ([]model.Remote, error) {
	return nil, nil
}
func (f *fakeStore) GetChainHead(context.Context, model.RemoteID) ([]byte, int64, error) {
	return nil, 0, nil
}
func (f *fakeStore) ReplayObservations(context.Context, model.RemoteID, model.Seq, int) ([]model.Observation, error) {
	return nil, nil
}
func (f *fakeStore) AppendTaintEvent(context.Context, *model.TaintEvent) (int64, error) {
	return 0, nil
}
func (f *fakeStore) ListTaintEvents(context.Context, model.RemoteID, int, int64) ([]model.TaintEvent, int64, error) {
	return nil, 0, nil
}
func (f *fakeStore) AckTaintEvent(context.Context, int64, string, string, int64) error { return nil }
func (f *fakeStore) ListSyncs(context.Context, model.RemoteID, int, int64) ([]model.Sync, int64, error) {
	return nil, 0, nil
}
func (f *fakeStore) TryAcquireLease(context.Context, model.RemoteID, string, int64, int64) (bool, []byte, error) {
	return false, nil, nil
}
func (f *fakeStore) ReleaseLeaseCAS(context.Context, model.RemoteID, string, []byte, []byte, int64) error {
	return nil
}
func (f *fakeStore) Migrate(context.Context) error { return nil }
func (f *fakeStore) Ping(context.Context) error    { return nil }
func (f *fakeStore) Close() error                  { return nil }

var _ model.Store = (*fakeStore)(nil)

// enabledCfg is the standard "cache on, TTL on" config for the behavioral tests.
func enabledCfg() Config { return Config{Enabled: true, MaxEntries: 1000, TTLNS: 60_000_000_000} }

// ---- tests -----------------------------------------------------------------

func TestDisabledConfigReturnsInnerUnwrapped(t *testing.T) {
	f := newFakeStore()
	got := Wrap(f, Config{Enabled: false})
	if got != model.Store(f) {
		t.Fatalf("Wrap with Enabled=false must return the inner store unchanged; got a different value")
	}
	// And a read must hit inner every time (no caching layer at all).
	f.seed(1, "https://x/y.git", 10, "v1")
	ctx := context.Background()
	for range 3 {
		if _, err := got.GetRemote(ctx, 1); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.getRemoteN.Load(); n != 3 {
		t.Fatalf("disabled pass-through: want 3 inner GetRemote calls, got %d", n)
	}
}

func TestCachedReadHitsInnerOnce(t *testing.T) {
	ctx := context.Background()
	t.Run("GetRemote", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/a.git", 10, "v1")
		c := Wrap(f, enabledCfg())
		for range 5 {
			if _, err := c.GetRemote(ctx, 1); err != nil {
				t.Fatal(err)
			}
		}
		if n := f.getRemoteN.Load(); n != 1 {
			t.Fatalf("GetRemote: want 1 inner call, got %d", n)
		}
	})
	t.Run("GetRef", func(t *testing.T) {
		f := newFakeStore()
		f.seed(2, "https://x/b.git", 20, "v2")
		c := Wrap(f, enabledCfg())
		for range 5 {
			if _, err := c.GetRef(ctx, 2, "v2"); err != nil {
				t.Fatal(err)
			}
		}
		if n := f.getRefN.Load(); n != 1 {
			t.Fatalf("GetRef: want 1 inner call, got %d", n)
		}
	})
	t.Run("ListTags", func(t *testing.T) {
		f := newFakeStore()
		f.seed(3, "https://x/c.git", 30, "v3")
		c := Wrap(f, enabledCfg())
		for range 5 {
			if _, err := c.ListTags(ctx, 3); err != nil {
				t.Fatal(err)
			}
		}
		if n := f.listTagsN.Load(); n != 1 {
			t.Fatalf("ListTags: want 1 inner call, got %d", n)
		}
	})
	t.Run("LatestObservationForRef", func(t *testing.T) {
		f := newFakeStore()
		f.seed(4, "https://x/d.git", 40, "v4")
		c := Wrap(f, enabledCfg())
		// LOBS is keyed by the ref's owning remote's generation, which it can only
		// know once the immutable refID→remoteID index is warm. On the verify hot
		// path GetRef always runs first and warms it (handlers.go: GetRef → LOBS),
		// so mirror that: warm via GetRef, then LOBS caches from its first call.
		mustGetRef(t, c, 4, "v4")
		for range 5 {
			if _, err := c.LatestObservationForRef(ctx, 40); err != nil {
				t.Fatal(err)
			}
		}
		if n := f.lobsN.Load(); n != 1 {
			t.Fatalf("LatestObservationForRef after index warm: want 1 inner call, got %d", n)
		}
	})

	// Cold index (LOBS called with no prior GetRef/ListTags): the FIRST call is
	// intentionally uncached (the owning remote — needed to key by generation — is
	// not yet known); the proof learns it, and the SECOND call onward caches.
	t.Run("LatestObservationForRef cold index first-call-uncached", func(t *testing.T) {
		f := newFakeStore()
		f.seed(5, "https://x/e.git", 50, "v5")
		c := Wrap(f, enabledCfg())
		for range 5 {
			if _, err := c.LatestObservationForRef(ctx, 50); err != nil {
				t.Fatal(err)
			}
		}
		if n := f.lobsN.Load(); n != 2 {
			t.Fatalf("LOBS cold index: want 2 inner calls (1 cold + 1 caching fill), got %d", n)
		}
	})
}

func TestGetRemoteByURLReusesPerRemoteEntry(t *testing.T) {
	ctx := context.Background()
	f := newFakeStore()
	f.seed(7, "https://x/url.git", 70, "v1")
	c := Wrap(f, enabledCfg())

	// First call resolves URL→ID (one GetRemoteByURL) and seeds the per-remote entry.
	if _, err := c.GetRemoteByURL(ctx, "https://x/url.git"); err != nil {
		t.Fatal(err)
	}
	// Subsequent GetRemoteByURL calls resolve via the URL→ID index and reuse the
	// per-remote GetRemote entry — inner GetRemoteByURL is hit exactly once total.
	for range 4 {
		if _, err := c.GetRemoteByURL(ctx, "https://x/url.git"); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.getByURLN.Load(); n != 1 {
		t.Fatalf("GetRemoteByURL: want 1 inner call (index reuse), got %d", n)
	}
	// A direct GetRemote(id) must ALSO be a hit (the by-URL fill seeded it).
	if _, err := c.GetRemote(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if n := f.getRemoteN.Load(); n != 0 {
		t.Fatalf("GetRemote after by-URL seed: want 0 inner calls, got %d", n)
	}
}

func TestWriteSurfacesInvalidate(t *testing.T) {
	ctx := context.Background()

	t.Run("UpdateRemote bumps that remote", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/a.git", 10, "v1")
		c := Wrap(f, enabledCfg())
		mustGetRemote(t, c, 1)
		mustGetRemote(t, c, 1) // cached → still 1 inner call
		if n := f.getRemoteN.Load(); n != 1 {
			t.Fatalf("pre-update: want 1 inner GetRemote, got %d", n)
		}
		if err := c.UpdateRemote(ctx, &model.Remote{ID: 1, NormalizedURL: "https://x/a.git"}); err != nil {
			t.Fatal(err)
		}
		mustGetRemote(t, c, 1) // gen bumped → MISS → re-call inner
		if n := f.getRemoteN.Load(); n != 2 {
			t.Fatalf("post-update: want 2 inner GetRemote, got %d", n)
		}
	})

	t.Run("SetRemoteHealth bumps that remote", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/a.git", 10, "v1")
		c := Wrap(f, enabledCfg())
		mustGetRemote(t, c, 1)
		if err := c.SetRemoteHealth(ctx, 1, model.RemoteActive, "", 123); err != nil {
			t.Fatal(err)
		}
		mustGetRemote(t, c, 1)
		if n := f.getRemoteN.Load(); n != 2 {
			t.Fatalf("SetRemoteHealth: want 2 inner GetRemote, got %d", n)
		}
	})

	t.Run("SoftDeleteRemote bumps remote and setGen", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/a.git", 10, "v1")
		c := Wrap(f, enabledCfg())
		// Warm the URL→ID index + per-remote entry.
		if _, err := c.GetRemoteByURL(ctx, "https://x/a.git"); err != nil {
			t.Fatal(err)
		}
		if err := c.SoftDeleteRemote(ctx, 1, 999); err != nil {
			t.Fatal(err)
		}
		// setGen bumped → URL→ID index key orphaned → by-URL re-hits inner.
		_, err := c.GetRemoteByURL(ctx, "https://x/a.git")
		if !errors.Is(err, model.ErrNotFound) {
			t.Fatalf("after delete, by-URL want ErrNotFound, got %v", err)
		}
		if n := f.getByURLN.Load(); n != 2 {
			t.Fatalf("SoftDeleteRemote: want 2 inner GetRemoteByURL (index re-resolve), got %d", n)
		}
	})

	t.Run("CreateRemote bumps setGen only", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/a.git", 10, "v1")
		c := Wrap(f, enabledCfg())
		// Negative by-URL lookup for a not-yet-existing remote is not cached (miss
		// returns an error and is not stored), so after create the new URL resolves.
		before := c.(*cachingStore).setGen.Load()
		if _, err := c.CreateRemote(ctx, &model.Remote{ID: 2, NormalizedURL: "https://x/new.git"}); err != nil {
			t.Fatal(err)
		}
		if after := c.(*cachingStore).setGen.Load(); after != before+1 {
			t.Fatalf("CreateRemote: setGen want %d, got %d", before+1, after)
		}
		// Per-remote gens are untouched by a create.
		if g := c.(*cachingStore).genOf(1); g != 0 {
			t.Fatalf("CreateRemote must not bump an existing remote's gen; got %d", g)
		}
	})

	t.Run("SetRefTaint bumps the ref's remote", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/a.git", 10, "v1")
		c := Wrap(f, enabledCfg())
		// Prime the refID→remoteID index by reading the ref once.
		if _, err := c.GetRef(ctx, 1, "v1"); err != nil {
			t.Fatal(err)
		}
		if _, err := c.GetRef(ctx, 1, "v1"); err != nil { // cached
			t.Fatal(err)
		}
		if n := f.getRefN.Load(); n != 1 {
			t.Fatalf("pre-taint: want 1 inner GetRef, got %d", n)
		}
		if err := c.SetRefTaint(ctx, 10, 555); err != nil {
			t.Fatal(err)
		}
		if _, err := c.GetRef(ctx, 1, "v1"); err != nil { // remote bumped → miss
			t.Fatal(err)
		}
		if n := f.getRefN.Load(); n != 2 {
			t.Fatalf("post-taint: want 2 inner GetRef, got %d", n)
		}
	})

	t.Run("SetRefTaint on never-cached ref is a no-op invalidation", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/a.git", 10, "v1")
		c := Wrap(f, enabledCfg()).(*cachingStore)
		// Ref 999 was never read → not in the index → bump nothing, but inner still called.
		if err := c.SetRefTaint(ctx, 999, 1); err != nil {
			t.Fatal(err)
		}
		if n := f.setRefTaintN.Load(); n != 1 {
			t.Fatalf("SetRefTaint must still delegate to inner; got %d", n)
		}
		if g := c.genOf(1); g != 0 {
			t.Fatalf("unrelated remote gen must stay 0; got %d", g)
		}
	})
}

func TestWithTxCommitBumpsTouchedRemotes(t *testing.T) {
	ctx := context.Background()
	f := newFakeStore()
	f.seed(1, "https://x/a.git", 10, "v1") // remote 1, ref 10
	f.seed(2, "https://x/b.git", 20, "v2") // remote 2, ref 20 (untouched by the tx)
	c := Wrap(f, enabledCfg())

	// Warm caches for both remotes' refs + obs proofs.
	mustGetRef(t, c, 1, "v1")
	mustGetRef(t, c, 2, "v2")
	mustLOBS(t, c, 10)
	mustLOBS(t, c, 20)
	if f.getRefN.Load() != 2 || f.lobsN.Load() != 2 {
		t.Fatalf("warm-up: want 2 GetRef + 2 LOBS, got %d/%d", f.getRefN.Load(), f.lobsN.Load())
	}

	// A transaction that upserts ref 10 (remote 1) only.
	err := c.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
		return tx.UpsertRefProjection(ctx, &model.Ref{ID: 10, RemoteID: 1, TagName: "v1"})
	})
	if err != nil {
		t.Fatal(err)
	}

	// Remote 1's ref + obs proof must MISS (re-call inner); remote 2's must stay cached.
	mustGetRef(t, c, 1, "v1")
	mustLOBS(t, c, 10)
	mustGetRef(t, c, 2, "v2")
	mustLOBS(t, c, 20)
	if got := f.getRefN.Load(); got != 3 {
		t.Fatalf("post-commit GetRef: want 3 (remote 1 re-read, remote 2 cached), got %d", got)
	}
	if got := f.lobsN.Load(); got != 3 {
		t.Fatalf("post-commit LOBS: want 3 (ref 10 re-read, ref 20 cached), got %d", got)
	}
}

func TestWithTxRollbackBumpsNothing(t *testing.T) {
	ctx := context.Background()

	t.Run("user-returned error", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/a.git", 10, "v1")
		c := Wrap(f, enabledCfg())
		mustGetRef(t, c, 1, "v1")
		wantErr := errors.New("boom")
		err := c.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
			_ = tx.UpsertRefProjection(ctx, &model.Ref{ID: 10, RemoteID: 1})
			return wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("want propagated error, got %v", err)
		}
		mustGetRef(t, c, 1, "v1") // must STILL be cached (rollback bumps nothing)
		if n := f.getRefN.Load(); n != 1 {
			t.Fatalf("rollback must not invalidate: want 1 inner GetRef, got %d", n)
		}
	})

	t.Run("commit failure", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/a.git", 10, "v1")
		f.failTx = errors.New("commit failed")
		c := Wrap(f, enabledCfg())
		mustGetRef(t, c, 1, "v1")
		err := c.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
			return tx.UpsertRefProjection(ctx, &model.Ref{ID: 10, RemoteID: 1})
		})
		if err == nil {
			t.Fatal("want commit error, got nil")
		}
		mustGetRef(t, c, 1, "v1")
		if n := f.getRefN.Load(); n != 1 {
			t.Fatalf("failed commit must not invalidate: want 1 inner GetRef, got %d", n)
		}
	})
}

// TestWriteErrorDoesNotBump asserts a failed single-shot write does not bump
// (only successful inner writes invalidate — the locked rule).
func TestWriteErrorDoesNotBump(t *testing.T) {
	ctx := context.Background()
	f := newFakeStore()
	f.seed(1, "https://x/a.git", 10, "v1")
	c := Wrap(f, enabledCfg())
	mustGetRemote(t, c, 1)
	f.failWrite = errors.New("update failed")
	if err := c.UpdateRemote(ctx, &model.Remote{ID: 1}); err == nil {
		t.Fatal("want update error, got nil")
	}
	mustGetRemote(t, c, 1) // must still be cached
	if n := f.getRemoteN.Load(); n != 1 {
		t.Fatalf("failed write must not invalidate: want 1 inner GetRemote, got %d", n)
	}
}

// TestRaceNoStaleBeyondCommit is the §4.8 race/correctness test. With TTL=0 (no
// time-based expiry — per-remote generation invalidation is the SOLE correctness
// mechanism), many concurrent verifiers (GetRemoteByURL → GetRef →
// LatestObservationForRef) race a writer mutating ref 10 via WithTx. The invariant
// (spec §4.5): once a write commits version v, no verifier may afterward observe a
// version < v. Each verifier snapshots the committed floor BEFORE its reads, so any
// value the reads return must be >= that floor — a version committed strictly
// before a read began can never be un-observed by that read. Run under -race.
func TestRaceNoStaleBeyondCommit(t *testing.T) {
	ctx := context.Background()
	f := newFakeStore()
	f.seed(1, "https://x/a.git", 10, "v1")
	c := Wrap(f, Config{Enabled: true, MaxEntries: 1000, TTLNS: 0})

	var committed atomic.Int64
	var failed atomic.Bool
	stop := make(chan struct{})
	const writes = 400
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(stop)
		for i := int64(1); i <= writes; i++ {
			if err := c.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
				return tx.UpsertRefProjection(ctx, &model.Ref{ID: 10, RemoteID: 1, TagName: "v1"})
			}); err != nil {
				failed.Store(true)
				return
			}
			f.mu.Lock()
			v := f.refVer[10]
			f.mu.Unlock()
			committed.Store(v)
		}
	}()

	const readers = 8
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Snapshot the floor BEFORE reading. Anything committed at-or-before now
				// must remain observable; the reads below must not return anything older.
				floor := committed.Load()
				// Full verify chain: resolve the remote by URL first (exercises the
				// URL→ID index + per-remote entry under concurrent generation bumps).
				if _, err := c.GetRemoteByURL(ctx, "https://x/a.git"); err != nil {
					failed.Store(true)
					return
				}
				ref, err := c.GetRef(ctx, 1, "v1")
				if err != nil {
					failed.Store(true)
					return
				}
				proof, err := c.LatestObservationForRef(ctx, 10)
				if err != nil {
					failed.Store(true)
					return
				}
				if int64(ref.ObservationCount) < floor {
					t.Errorf("STALE GetRef: observed v%d < pre-read committed v%d", ref.ObservationCount, floor)
					failed.Store(true)
					return
				}
				if int64(proof.Seq) < floor {
					t.Errorf("STALE LOBS: observed seq %d < pre-read committed v%d", proof.Seq, floor)
					failed.Store(true)
					return
				}
			}
		}()
	}

	wg.Wait()
	if failed.Load() {
		t.Fatal("strict no-stale-beyond-commit invariant violated")
	}
}

// ---- test helpers ----------------------------------------------------------

func mustGetRemote(t *testing.T, c model.Store, id model.RemoteID) {
	t.Helper()
	if _, err := c.GetRemote(context.Background(), id); err != nil {
		t.Fatalf("GetRemote(%d): %v", id, err)
	}
}

func mustGetRef(t *testing.T, c model.Store, remoteID model.RemoteID, tag string) {
	t.Helper()
	if _, err := c.GetRef(context.Background(), remoteID, tag); err != nil {
		t.Fatalf("GetRef(%d,%q): %v", remoteID, tag, err)
	}
}

func mustLOBS(t *testing.T, c model.Store, refID model.RefID) {
	t.Helper()
	if _, err := c.LatestObservationForRef(context.Background(), refID); err != nil {
		t.Fatalf("LatestObservationForRef(%d): %v", refID, err)
	}
}

// TestReturnedObjectsAreIsolatedFromCache pins the value-isolation contract: the
// bare store hands out a freshly-scanned object every read, so callers may mutate
// what they receive — the UpdateRemote handler reads a Remote and sets fields
// before writing it back; the sync writer flips Deleted/LastSeen on a ListTags
// element before UpsertRefProjection. The cache must return copies so those
// in-place mutations never corrupt the cached entry (and never race a concurrent
// verifier reading the same pointer). Without per-read copies each sub-test below
// fails: the mutation made to the first result reappears on the cache hit.
func TestReturnedObjectsAreIsolatedFromCache(t *testing.T) {
	ctx := context.Background()

	t.Run("GetRemote", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/r.git", 10, "v1")
		c := Wrap(f, enabledCfg())

		r1, err := c.GetRemote(ctx, 1) // miss → fills cache
		if err != nil {
			t.Fatal(err)
		}
		r1.Status = model.RemotePaused // caller mutates what it received
		r1.SyncIntervalNS = 999

		r2, err := c.GetRemote(ctx, 1) // hit → must be a pristine copy
		if err != nil {
			t.Fatal(err)
		}
		if r2.Status == model.RemotePaused || r2.SyncIntervalNS == 999 {
			t.Fatalf("caller mutation leaked into the cache: Status=%q interval=%d", r2.Status, r2.SyncIntervalNS)
		}
		if n := f.getRemoteN.Load(); n != 1 {
			t.Fatalf("want 1 inner GetRemote (2nd served from cache), got %d", n)
		}
	})

	t.Run("GetRemoteByURL", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/r.git", 10, "v1")
		c := Wrap(f, enabledCfg())

		r1, err := c.GetRemoteByURL(ctx, "https://x/r.git")
		if err != nil {
			t.Fatal(err)
		}
		r1.Status = model.RemotePaused

		r2, err := c.GetRemoteByURL(ctx, "https://x/r.git")
		if err != nil {
			t.Fatal(err)
		}
		if r2.Status == model.RemotePaused {
			t.Fatalf("caller mutation leaked into the URL-resolved cache: Status=%q", r2.Status)
		}
	})

	t.Run("GetRef", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/r.git", 10, "v1")
		c := Wrap(f, enabledCfg())

		ref1, err := c.GetRef(ctx, 1, "v1")
		if err != nil {
			t.Fatal(err)
		}
		ref1.Deleted = true
		ref1.Tainted = true

		ref2, err := c.GetRef(ctx, 1, "v1")
		if err != nil {
			t.Fatal(err)
		}
		if ref2.Deleted || ref2.Tainted {
			t.Fatalf("caller mutation leaked into the Ref cache: Deleted=%v Tainted=%v", ref2.Deleted, ref2.Tainted)
		}
	})

	t.Run("ListTags", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/r.git", 10, "v1")
		c := Wrap(f, enabledCfg())

		l1, err := c.ListTags(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(l1) == 0 {
			t.Fatal("want >=1 tag")
		}
		l1[0].Deleted = true // mirrors the sync writer mutating prev.Deleted in place
		l1[0].LastSeenNS = 12345

		l2, err := c.ListTags(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		if l2[0].Deleted || l2[0].LastSeenNS == 12345 {
			t.Fatalf("caller mutation leaked into the ListTags cache: Deleted=%v LastSeen=%d", l2[0].Deleted, l2[0].LastSeenNS)
		}
	})

	t.Run("LatestObservationForRef", func(t *testing.T) {
		f := newFakeStore()
		f.seed(1, "https://x/r.git", 10, "v1")
		c := Wrap(f, enabledCfg())

		// Warm the refID->remoteID index so LOBS caches (its cold path is uncached).
		if _, err := c.GetRef(ctx, 1, "v1"); err != nil {
			t.Fatal(err)
		}
		p1, err := c.LatestObservationForRef(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		p1.Seq = 777

		p2, err := c.LatestObservationForRef(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		if p2.Seq == 777 {
			t.Fatalf("caller mutation leaked into the LOBS cache: Seq=%d", p2.Seq)
		}
	})
}
