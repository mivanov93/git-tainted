// Package cache provides an Otter-backed caching decorator over model.Store for
// the verify hot path (control-plane design spec §4). It caches the five read
// methods the Verify request issues (GetRemoteByURL/GetRemote → GetRef →
// LatestObservationForRef, plus ListTags) and invalidates them with per-remote
// GENERATION counters: a flat KV cache cannot enumerate keys by remote, so every
// cache key embeds its remote's current generation, and "invalidate remote N" is
// a single atomic increment of gens[N] that orphans all of N's prior-generation
// keys instantly (Otter reclaims them lazily; the TTL is a backstop).
//
// The single locked correctness invariant (spec §4.5): a write bumps the touched
// remote's generation STRICTLY AFTER the underlying inner write returns success.
// A concurrent Verify either (a) read+cached under the old generation before the
// commit — the post-commit bump orphans that key, so the next read misses and
// re-reads fresh — or (b) read after the bump and already saw the new generation.
// No interleaving serves a post-commit value under a live generation beyond TTL.
//
// Wrap returns inner UNCHANGED when cfg.Enabled is false, so the seam is provably
// transparent (zero overhead, identical behavior). All reads/writes are lock-free
// (Otter is lock-free; generations are atomics); no goroutines are added beyond
// Otter's internal maintenance.
package cache

import (
	"context"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maypok86/otter/v2"

	"github.com/mivanov93/git-tainted/internal/model"
)

// Config controls the caching decorator (spec §4.6). Zero value is a disabled
// cache (Enabled=false), so Wrap(inner, Config{}) == inner.
type Config struct {
	// Enabled turns the decorator on. When false, Wrap returns inner unchanged.
	Enabled bool
	// MaxEntries bounds each logical Otter cache (size-based S3-FIFO eviction).
	MaxEntries int
	// TTL is the staleness backstop, independent of the (immediate) generation
	// invalidation. 0 disables TTL expiry entirely — the generation mechanism
	// alone then governs correctness.
	TTL time.Duration
}

// cachingStore decorates an inner model.Store. It EMBEDS the inner Store so every
// method not explicitly overridden below is promoted and passes straight through
// (audit lists, chain replay, lease ops, Migrate/Ping/Close, …). It overrides only
// the cached reads and the writes that must invalidate.
type cachingStore struct {
	model.Store // promoted pass-through for everything not overridden

	// gens holds RemoteID → *atomic.Uint64 (the per-remote generation). A missing
	// entry means generation 0. genOf lazily materializes a counter so bump and
	// read agree on one cell. sync.Map fits the "write-rarely, read-often, keys
	// stabilize" access pattern (one cell per remote, created once).
	gens sync.Map // map[model.RemoteID]*atomic.Uint64

	// setGen is the global remote-SET generation, bumped only on membership change
	// (CreateRemote / SoftDeleteRemote). It backs the URL→ID index (and ListRemotes
	// if it were cached) so a create/delete cannot serve a stale id resolution.
	setGen atomic.Uint64

	// refRemote is a lazily-populated, NEVER-invalidated refID → RemoteID index
	// (a ref's owning remote is immutable). It lets the refID-keyed methods
	// (LatestObservationForRef, SetRefTaint) resolve the remote whose generation
	// to embed/bump. sync.Map: insert-once, read-often.
	refRemote sync.Map // map[model.RefID]model.RemoteID

	// urlID maps a normalized URL → RemoteID for the current setGen. Keyed by
	// (setGen, normURL); a create/delete bumps setGen and orphans prior entries.
	urlID *otter.Cache[string, model.RemoteID]

	// remoteByID caches GetRemote results keyed (remoteID, gen).
	remoteByID *otter.Cache[string, *model.Remote]
	// ref caches GetRef results keyed (remoteID, gen, tagName).
	ref *otter.Cache[string, *model.Ref]
	// lobs caches LatestObservationForRef keyed (refID, remoteGen).
	lobs *otter.Cache[string, *model.ObservationProof]
	// tags caches ListTags keyed (remoteID, gen).
	tags *otter.Cache[string, []model.Ref]
}

// Compile-time proof the decorator satisfies the full Store seam.
var _ model.Store = (*cachingStore)(nil)

// Wrap decorates inner with the caching layer. When cfg.Enabled is false it
// returns inner unchanged (zero overhead, provably transparent — spec §4.2/§4.6).
func Wrap(inner model.Store, cfg Config) model.Store {
	if !cfg.Enabled {
		return inner
	}
	cs := &cachingStore{Store: inner}
	cs.urlID = newOtter[string, model.RemoteID](cfg)
	cs.remoteByID = newOtter[string, *model.Remote](cfg)
	cs.ref = newOtter[string, *model.Ref](cfg)
	cs.lobs = newOtter[string, *model.ObservationProof](cfg)
	cs.tags = newOtter[string, []model.Ref](cfg)
	return cs
}

// newOtter builds one bounded (+optionally TTL'd) Otter cache. TTL<=0 attaches
// no ExpiryCalculator so entries never expire on time — generation invalidation
// is then the sole correctness mechanism (exercised by the TTL=0 race test).
func newOtter[K comparable, V any](cfg Config) *otter.Cache[K, V] {
	maxEntries := cfg.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 100_000
	}
	opts := &otter.Options[K, V]{MaximumSize: maxEntries}
	if cfg.TTL > 0 {
		opts.ExpiryCalculator = otter.ExpiryWriting[K, V](cfg.TTL)
	}
	return otter.Must(opts)
}

// ---- value isolation -------------------------------------------------------
// The bare store returns a freshly-scanned object on every read, so callers may
// safely mutate what they receive — the UpdateRemote handler reads a Remote then
// sets fields before writing it back, and the sync writer flips Deleted/LastSeen
// on a prior Ref obtained from ListTags. The cache hands out objects it OWNS, so
// it MUST return a copy to preserve that contract; otherwise a caller's in-place
// mutation corrupts the cached entry and races concurrent readers. Shallow struct
// copies suffice: callers only mutate value fields, never the contents of the
// shared slice/pointer fields (chain hashes, oids), which are read-only everywhere.

func cloneRemote(r *model.Remote) *model.Remote { cp := *r; return &cp }
func cloneRef(r *model.Ref) *model.Ref          { cp := *r; return &cp }

func cloneProof(p *model.ObservationProof) *model.ObservationProof { cp := *p; return &cp }

// ---- generation helpers ----------------------------------------------------

// genCell returns the live atomic generation cell for id, creating it (at 0) on
// first touch so a later bump and a concurrent read share the same cell.
func (c *cachingStore) genCell(id model.RemoteID) *atomic.Uint64 {
	if v, ok := c.gens.Load(id); ok {
		return v.(*atomic.Uint64) //nolint:forcetypeassert // only this type is ever stored
	}
	cell := new(atomic.Uint64)
	actual, _ := c.gens.LoadOrStore(id, cell)
	return actual.(*atomic.Uint64) //nolint:forcetypeassert // only this type is ever stored
}

// genOf reads id's current generation (0 if the remote was never touched).
func (c *cachingStore) genOf(id model.RemoteID) uint64 { return c.genCell(id).Load() }

// bump invalidates remote id by atomically advancing its generation, orphaning
// every prior-generation key for that remote. MUST be called only after the
// underlying write has committed (the locked rule).
func (c *cachingStore) bump(id model.RemoteID) { c.genCell(id).Add(1) }

// rememberRef records a ref's immutable owning remote in the never-invalidated
// refID→remoteID index (used to key/invalidate the refID-keyed methods).
func (c *cachingStore) rememberRef(refID model.RefID, remoteID model.RemoteID) {
	// LoadOrStore (not Store) keeps the first witnessed mapping; a ref's remote is
	// immutable, so any later write would be identical anyway.
	c.refRemote.LoadOrStore(refID, remoteID)
}

// remoteOfRef returns the cached owning remote of refID, if known.
func (c *cachingStore) remoteOfRef(refID model.RefID) (model.RemoteID, bool) {
	if v, ok := c.refRemote.Load(refID); ok {
		return v.(model.RemoteID), true //nolint:forcetypeassert // only this type is ever stored
	}
	return 0, false
}

// ---- key builders ----------------------------------------------------------
// Keys embed the relevant generation so a bump makes prior keys unreachable.
// strconv.AppendInt over a small reused builder avoids fmt allocs on the hot path.

func key2(prefix string, a, b int64) string {
	b2 := make([]byte, 0, len(prefix)+1+20+1+20)
	b2 = append(b2, prefix...)
	b2 = append(b2, '|')
	b2 = strconv.AppendInt(b2, a, 10)
	b2 = append(b2, '|')
	b2 = strconv.AppendInt(b2, b, 10)
	return string(b2)
}

func keyRemote(remoteID model.RemoteID, gen uint64) string {
	return key2("remote", int64(remoteID), int64(gen)) //nolint:gosec // gen fits int64 in any realistic lifetime
}

func keyTags(remoteID model.RemoteID, gen uint64) string {
	return key2("tags", int64(remoteID), int64(gen)) //nolint:gosec // gen fits int64
}

func keyLobs(refID model.RefID, remoteGen uint64) string {
	return key2("lobs", int64(refID), int64(remoteGen)) //nolint:gosec // gen fits int64
}

func keyURL(setGen uint64, normURL string) string {
	b := make([]byte, 0, 6+20+1+len(normURL))
	b = append(b, "byurl|"...)
	b = strconv.AppendInt(b, int64(setGen), 10) //nolint:gosec // setGen fits int64
	b = append(b, '|')
	b = append(b, normURL...)
	return string(b)
}

func keyRef(remoteID model.RemoteID, gen uint64, tag string) string {
	b := make([]byte, 0, 4+20+1+20+1+len(tag))
	b = append(b, "ref|"...)
	b = strconv.AppendInt(b, int64(remoteID), 10)
	b = append(b, '|')
	b = strconv.AppendInt(b, int64(gen), 10) //nolint:gosec // gen fits int64
	b = append(b, '|')
	b = append(b, tag...)
	return string(b)
}

// ---- cached reads ----------------------------------------------------------
// Each read snapshots the generation BEFORE calling inner and fills under that
// same generation, so a write committing during the fill bumps past it (spec §4.5).

func (c *cachingStore) GetRemote(ctx context.Context, id model.RemoteID) (*model.Remote, error) {
	gen := c.genOf(id)
	k := keyRemote(id, gen)
	if v, ok := c.remoteByID.GetIfPresent(k); ok {
		return cloneRemote(v), nil
	}
	r, err := c.Store.GetRemote(ctx, id)
	if err != nil {
		return nil, err //nolint:wrapcheck // transparent decorator: preserve the store's sentinel errors verbatim
	}
	c.remoteByID.Set(k, r)
	return cloneRemote(r), nil
}

func (c *cachingStore) GetRemoteByURL(ctx context.Context, normalizedURL string) (*model.Remote, error) {
	sg := c.setGen.Load()
	uk := keyURL(sg, normalizedURL)
	// Resolve URL→ID via the index, then reuse the per-remote GetRemote entry.
	if id, ok := c.urlID.GetIfPresent(uk); ok {
		return c.GetRemote(ctx, id)
	}
	r, err := c.Store.GetRemoteByURL(ctx, normalizedURL)
	if err != nil {
		return nil, err //nolint:wrapcheck // transparent decorator: preserve store sentinels
	}
	c.urlID.Set(uk, r.ID)
	// Also seed the per-remote entry so a subsequent GetRemote(id) hits — but under
	// a generation guard: if a write committed (and bumped) between the fetch above
	// and this seed, drop the entry so a stale remote is never visible under a live
	// generation (§4.5). The next GetRemote re-fetches fresh.
	g := c.genOf(r.ID)
	rk := keyRemote(r.ID, g)
	c.remoteByID.Set(rk, r)
	if c.genOf(r.ID) != g {
		c.remoteByID.Invalidate(rk)
	}
	return cloneRemote(r), nil
}

func (c *cachingStore) GetRef(ctx context.Context, remoteID model.RemoteID, tagName string) (*model.Ref, error) {
	gen := c.genOf(remoteID)
	k := keyRef(remoteID, gen, tagName)
	if v, ok := c.ref.GetIfPresent(k); ok {
		return cloneRef(v), nil
	}
	r, err := c.Store.GetRef(ctx, remoteID, tagName)
	if err != nil {
		return nil, err //nolint:wrapcheck // transparent decorator: preserve store sentinels
	}
	// Populate the immutable refID→remoteID index for the refID-keyed methods.
	c.rememberRef(r.ID, r.RemoteID)
	c.ref.Set(k, r)
	return cloneRef(r), nil
}

func (c *cachingStore) ListTags(ctx context.Context, remoteID model.RemoteID) ([]model.Ref, error) {
	gen := c.genOf(remoteID)
	k := keyTags(remoteID, gen)
	if v, ok := c.tags.GetIfPresent(k); ok {
		return slices.Clone(v), nil
	}
	refs, err := c.Store.ListTags(ctx, remoteID)
	if err != nil {
		return nil, err //nolint:wrapcheck // transparent decorator: preserve store sentinels
	}
	// Seed the refID→remoteID index from every listed ref.
	for i := range refs {
		c.rememberRef(refs[i].ID, refs[i].RemoteID)
	}
	c.tags.Set(k, refs)
	return slices.Clone(refs), nil
}

func (c *cachingStore) LatestObservationForRef(ctx context.Context, refID model.RefID) (*model.ObservationProof, error) {
	// A LOBS entry MUST be keyed under the generation that was current when its
	// inner read happened (§4.5), so that a write committing during the fill bumps
	// past it. That requires knowing the owning remote (immutable) BEFORE the read,
	// which only the index gives us. So:
	//   - warm index → snapshot gen, read under it, cache under the SAME gen;
	//   - cold index → we can't key correctly yet, so read inner WITHOUT caching and
	//     just learn the remote from the proof; the next call's index is warm and
	//     caches properly. (At most the first read per ref is uncached — bounded.)
	rid, known := c.remoteOfRef(refID)
	if !known {
		p, err := c.Store.LatestObservationForRef(ctx, refID)
		if err != nil {
			return nil, err //nolint:wrapcheck // transparent decorator: preserve store sentinels
		}
		c.rememberRef(refID, p.RemoteID) // warm the index for subsequent calls
		return cloneProof(p), nil
	}
	gen := c.genOf(rid) // snapshot BEFORE the read; the fill uses this same gen
	k := keyLobs(refID, gen)
	if v, ok := c.lobs.GetIfPresent(k); ok {
		return cloneProof(v), nil
	}
	p, err := c.Store.LatestObservationForRef(ctx, refID)
	if err != nil {
		return nil, err //nolint:wrapcheck // transparent decorator: preserve store sentinels
	}
	// Cache under the pre-read generation: if a write committed during the read it
	// already bumped rid past `gen`, orphaning this key so the next read re-fetches.
	c.lobs.Set(k, p)
	return cloneProof(p), nil
}

// ---- invalidating writes ---------------------------------------------------
// Each delegates to inner, then bumps STRICTLY AFTER inner returns success.

func (c *cachingStore) CreateRemote(ctx context.Context, r *model.Remote) (model.RemoteID, error) {
	id, err := c.Store.CreateRemote(ctx, r)
	if err != nil {
		return id, err //nolint:wrapcheck // transparent decorator: preserve store sentinels (ErrConflict)
	}
	// Membership changed → bump the remote-set generation (orphans URL→ID entries).
	c.setGen.Add(1)
	return id, nil
}

func (c *cachingStore) UpdateRemote(ctx context.Context, r *model.Remote) error {
	if err := c.Store.UpdateRemote(ctx, r); err != nil {
		return err //nolint:wrapcheck // transparent decorator: preserve store sentinels
	}
	c.bump(r.ID)
	return nil
}

func (c *cachingStore) SoftDeleteRemote(ctx context.Context, id model.RemoteID, atNS int64) error {
	if err := c.Store.SoftDeleteRemote(ctx, id, atNS); err != nil {
		return err //nolint:wrapcheck // transparent decorator: preserve store sentinels
	}
	c.bump(id)      // existing per-remote keys (remote|ref|tags|lobs) go stale
	c.setGen.Add(1) // membership changed → URL→ID index resolution must re-fetch
	return nil
}

func (c *cachingStore) SetRemoteHealth(ctx context.Context, id model.RemoteID, status model.RemoteStatus, lastErr string, lastOkNS int64) error {
	if err := c.Store.SetRemoteHealth(ctx, id, status, lastErr, lastOkNS); err != nil {
		return err //nolint:wrapcheck // transparent decorator: preserve store sentinels
	}
	// last_ok_ns / status feed verify staleness → invalidate the remote's reads.
	c.bump(id)
	return nil
}

func (c *cachingStore) SetRefTaint(ctx context.Context, refID model.RefID, firstNS int64) error {
	if err := c.Store.SetRefTaint(ctx, refID, firstNS); err != nil {
		return err //nolint:wrapcheck // transparent decorator: preserve store sentinels
	}
	// Resolve the ref's remote via the immutable index and bump it; no-op (nothing
	// to invalidate) if the ref was never cached through this decorator.
	if rid, ok := c.remoteOfRef(refID); ok {
		c.bump(rid)
	}
	return nil
}

// ---- WithTx capture --------------------------------------------------------

// WithTx wraps the user closure's Tx with a capturing Tx that records the set of
// remoteIDs the transaction touches. On commit (real WithTx returns nil) every
// recorded remote is bumped; on rollback (error) nothing is bumped, so the cache
// keeps reflecting the still-committed prior state. The recorded set lives on the
// per-call wrapper, so concurrent transactions never share it (spec §4.4).
func (c *cachingStore) WithTx(ctx context.Context, fn func(ctx context.Context, tx model.Tx) error) error {
	capt := &captureTx{cs: c}
	err := c.Store.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
		capt.inner = tx
		return fn(ctx, capt)
	})
	if err != nil {
		return err //nolint:wrapcheck // transparent decorator: preserve store sentinels; rollback bumps nothing
	}
	// Commit succeeded → bump every touched remote, strictly after the write.
	capt.flush()
	return nil
}

// captureTx delegates every Tx method to the real tx and records the remoteIDs it
// observes. touched is per-call (one captureTx per WithTx invocation), so no
// cross-transaction sharing; bumps happen only via flush() after a successful
// commit. It is used single-goroutine within one WithTx closure (the store's tx
// contract), so the plain map needs no locking.
type captureTx struct {
	cs      *cachingStore
	inner   model.Tx
	touched map[model.RemoteID]struct{}
	// createdRemote records that the txn added at least one remote, so flush()
	// bumps the remote-SET generation on commit (membership changed) — mirroring
	// the top-level cache.CreateRemote. A brand-new remote has nothing cached, so
	// no per-remote generation bump is needed (only the URL→ID index must refresh).
	createdRemote bool
}

func (t *captureTx) mark(id model.RemoteID) {
	if t.touched == nil {
		t.touched = make(map[model.RemoteID]struct{}, 1)
	}
	t.touched[id] = struct{}{}
}

// flush bumps every recorded remote's generation. Called only on commit. If the
// txn created a remote, it also bumps the remote-SET generation so a stale URL→ID
// resolution cannot survive the membership change (mirrors cache.CreateRemote).
func (t *captureTx) flush() {
	for id := range t.touched {
		t.cs.bump(id)
	}
	if t.createdRemote {
		t.cs.setGen.Add(1)
	}
}

func (t *captureTx) AppendObservation(ctx context.Context, o *model.Observation) (model.Seq, error) {
	t.mark(o.RemoteID)
	return t.inner.AppendObservation(ctx, o) //nolint:wrapcheck // transparent delegation
}

func (t *captureTx) UpsertRefProjection(ctx context.Context, ref *model.Ref) error {
	t.mark(ref.RemoteID)
	// The projection also teaches us the ref's owning remote (once ref.ID is set).
	if ref.ID != 0 {
		t.cs.rememberRef(ref.ID, ref.RemoteID)
	}
	return t.inner.UpsertRefProjection(ctx, ref) //nolint:wrapcheck // transparent delegation
}

func (t *captureTx) WriteSync(ctx context.Context, s *model.Sync) (model.SyncID, error) {
	// WriteSync carries a RemoteID too; mark it so a sync that writes only the audit
	// row (no tag changes) still refreshes that remote's reads (e.g. chain head).
	t.mark(s.RemoteID)
	return t.inner.WriteSync(ctx, s) //nolint:wrapcheck // transparent delegation
}

func (t *captureTx) AdvanceChainHead(ctx context.Context, remoteID model.RemoteID, newHead []byte, newLen int64) error {
	t.mark(remoteID)
	return t.inner.AdvanceChainHead(ctx, remoteID, newHead, newLen) //nolint:wrapcheck // transparent delegation
}

func (t *captureTx) AppendTaintEvent(ctx context.Context, e *model.TaintEvent) (int64, error) {
	t.mark(e.RemoteID)
	return t.inner.AppendTaintEvent(ctx, e) //nolint:wrapcheck // transparent delegation
}

func (t *captureTx) CreateRemote(ctx context.Context, r *model.Remote) (model.RemoteID, error) {
	id, err := t.inner.CreateRemote(ctx, r)
	if err != nil {
		return id, err //nolint:wrapcheck // transparent delegation: preserve store sentinels (ErrConflict)
	}
	// Membership changed → flush() bumps the remote-SET generation on commit. A new
	// remote has nothing cached, so no per-remote gen bump is taken (spec §4.5).
	t.createdRemote = true
	return id, nil
}

func (t *captureTx) CountAllRemotes(ctx context.Context) (int64, error) {
	// Pure read on the txn's connection; nothing to invalidate.
	return t.inner.CountAllRemotes(ctx) //nolint:wrapcheck // transparent delegation
}

// Compile-time proof the capturing Tx satisfies model.Tx.
var _ model.Tx = (*captureTx)(nil)
