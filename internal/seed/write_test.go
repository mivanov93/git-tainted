package seed

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/mivanov93/git-tainted/internal/config"
	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/testutil"
)

// mustOID parses a hex oid for a test (inferring algo from width).
func mustOID(t *testing.T, hexStr string) model.OID {
	t.Helper()
	o, err := parseHexOID(hexStr)
	if err != nil {
		t.Fatalf("parseHexOID(%q): %v", hexStr, err)
	}
	return o
}

// newTestSeeder builds a Seeder over a real store with default seed config.
func newTestSeeder(t *testing.T, store model.Store) *Seeder {
	t.Helper()
	cfg := &config.Config{
		SeedServers:         "https://peer", // makes SeedEnabled() true
		SeedQuorum:          1,
		SeedConcurrency:     8,
		SeedTimeout:         30 * time.Second,
		SeedMaxRemotes:      5000,
		SeedMaxObservations: 200_000,
		SeedMaxPages:        10_000,
		SyncDefaultInterval: 5 * time.Minute,
		StalenessBudget:     time.Hour,
	}
	clk := testutil.NewFakeClock(1_700_000_000_000_000_000)
	return New(nil, store, cfg, clk, slog.New(slog.NewTextHandler(testWriter{t}, nil)))
}

// testWriter routes slog output to t.Log.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) { w.t.Logf("%s", p); return len(p), nil }

// --- chain rebuild: clean tag ----------------------------------------------

func TestWrite_CleanTag_ChainIntact(t *testing.T) {
	ctx := context.Background()
	store := testutil.NewTestStore(t)
	s := newTestSeeder(t, store)

	res := mergeResult{
		remotes: []mergedRemote{{
			url: "https://example.com/owner/repo", normalizedURL: "https://example.com/owner/repo",
			transport: model.TransportHTTPS, taintAnyTagDeletion: true,
			tags: []mergedTag{{
				name: "v1", firstOID: mustOID(t, oidA), isAnnotated: false,
				firstSeenNS: 1000, currentOID: mustOID(t, oidA), currentPeeledOID: mustOID(t, oidA),
				lastSeenNS: 2000,
			}},
		}},
		totalObs: 1,
	}
	rA, tA, err := s.write(ctx, res)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if rA != 1 || tA != 1 {
		t.Fatalf("adopted remotes=%d tags=%d, want 1/1", rA, tA)
	}

	r, err := store.GetRemoteByURL(ctx, "https://example.com/owner/repo")
	if err != nil {
		t.Fatalf("GetRemoteByURL: %v", err)
	}
	testutil.AssertChainIntact(t, ctx, store, r.ID)

	ref, err := store.GetRef(ctx, r.ID, "v1")
	if err != nil {
		t.Fatalf("GetRef: %v", err)
	}
	if ref.FirstOID.Hex() != oidA {
		t.Errorf("first_oid = %s, want %s", ref.FirstOID.Hex(), oidA)
	}
	if ref.ObservationCount != 1 {
		t.Errorf("observation_count = %d, want 1", ref.ObservationCount)
	}
	if ref.Tainted {
		t.Error("clean tag must not be tainted")
	}
	// One genesis observation, correct event type.
	obs, err := store.ReplayObservations(ctx, r.ID, 0, 100)
	if err != nil {
		t.Fatalf("ReplayObservations: %v", err)
	}
	if len(obs) != 1 || obs[0].EventType != model.EventTagCreated {
		t.Fatalf("want 1 tag_created observation, got %+v", obs)
	}
	if obs[0].NewOID.Hex() != oidA {
		t.Errorf("genesis new_oid = %s, want %s", obs[0].NewOID.Hex(), oidA)
	}
}

// --- chain rebuild: tainted tag with continuous events ----------------------

func TestWrite_TaintedTag_ChainIntactAndContinuous(t *testing.T) {
	ctx := context.Background()
	store := testutil.NewTestStore(t)
	s := newTestSeeder(t, store)

	r := model.TaintTagOIDChanged
	res := mergeResult{
		remotes: []mergedRemote{{
			url: "https://example.com/owner/repo", normalizedURL: "https://example.com/owner/repo",
			transport: model.TransportHTTPS, taintAnyTagDeletion: true,
			tags: []mergedTag{{
				name: "v1", firstOID: mustOID(t, oidA),
				firstSeenNS: 1000, currentOID: mustOID(t, oidC), currentPeeledOID: mustOID(t, oidC),
				lastSeenNS: 8000, tainted: true, taintFirstNS: ip(5000),
				events: []mergedEvent{
					{eventType: model.EventTagOIDChanged, taintReason: &r, fromOID: mustOID(t, oidA), toOID: mustOID(t, oidB), detectedAtNS: 5000},
					{eventType: model.EventTagOIDChanged, taintReason: &r, fromOID: mustOID(t, oidB), toOID: mustOID(t, oidC), detectedAtNS: 7000},
				},
			}},
		}},
		totalObs: 3,
	}
	if _, _, err := s.write(ctx, res); err != nil {
		t.Fatalf("write: %v", err)
	}

	rem, _ := store.GetRemoteByURL(ctx, "https://example.com/owner/repo")
	testutil.AssertChainIntact(t, ctx, store, rem.ID)

	ref, _ := store.GetRef(ctx, rem.ID, "v1")
	if !ref.Tainted || ref.TaintFirstNS == nil || *ref.TaintFirstNS != 5000 {
		t.Errorf("ref taint wrong: tainted=%v first=%v", ref.Tainted, ref.TaintFirstNS)
	}
	if ref.CurrentOID.Hex() != oidC {
		t.Errorf("current_oid = %s, want %s", ref.CurrentOID.Hex(), oidC)
	}
	if ref.ObservationCount != 3 {
		t.Errorf("observation_count = %d, want 3", ref.ObservationCount)
	}

	// Oid-continuity: replay and verify from[i]==to[i-1], first from==first_oid.
	obs, _ := store.ReplayObservations(ctx, rem.ID, 0, 100)
	if len(obs) != 3 {
		t.Fatalf("want 3 observations, got %d", len(obs))
	}
	assertOIDContinuity(t, mustOID(t, oidA), obs)

	// Two taint_events rows.
	evs, _, err := store.ListTaintEvents(ctx, rem.ID, 100, 0)
	if err != nil {
		t.Fatalf("ListTaintEvents: %v", err)
	}
	if len(evs) != 2 {
		t.Errorf("want 2 taint events, got %d", len(evs))
	}
}

// assertOIDContinuity checks first from_oid == firstOID and from[i]==to[i-1]
// across the post-genesis observations (mirrors §6's continuity assertion).
func assertOIDContinuity(t *testing.T, firstOID model.OID, obs []model.Observation) {
	t.Helper()
	if len(obs) == 0 {
		return
	}
	if obs[0].EventType != model.EventTagCreated {
		t.Errorf("first observation must be tag_created, got %s", obs[0].EventType)
	}
	if obs[0].NewOID.Hex() != firstOID.Hex() {
		t.Errorf("genesis new_oid %s != first_oid %s", obs[0].NewOID.Hex(), firstOID.Hex())
	}
	var prevNew = obs[0].NewOID
	for i := 1; i < len(obs); i++ {
		o := obs[i]
		// from_oid must chain from the previous new_oid (unless recreation-from-empty).
		if !o.PrevOID.IsZero() {
			if o.PrevOID.Hex() != prevNew.Hex() {
				t.Errorf("obs[%d] prev_oid %s != previous new_oid %s", i, o.PrevOID.Hex(), prevNew.Hex())
			}
		}
		if !o.NewOID.IsZero() {
			prevNew = o.NewOID
		}
	}
}

// --- deletion event types via the write path --------------------------------

func TestWrite_DeleteRecreate_EventTypesPersisted(t *testing.T) {
	ctx := context.Background()
	store := testutil.NewTestStore(t)
	s := newTestSeeder(t, store)

	rDel := model.TaintTagDeletedRecreated
	res := mergeResult{
		remotes: []mergedRemote{{
			url: "https://example.com/owner/repo", normalizedURL: "https://example.com/owner/repo",
			transport: model.TransportHTTPS, taintAnyTagDeletion: true,
			tags: []mergedTag{{
				name: "v1", firstOID: mustOID(t, oidA), firstSeenNS: 1000,
				currentOID: mustOID(t, oidC), currentPeeledOID: mustOID(t, oidC), lastSeenNS: 8000,
				tainted: true, taintFirstNS: ip(6000),
				events: []mergedEvent{
					{eventType: model.EventTagDeleted, taintReason: &rDel, fromOID: mustOID(t, oidA), detectedAtNS: 6000},
					{eventType: model.EventTagRecreated, taintReason: &rDel, toOID: mustOID(t, oidC), detectedAtNS: 7000},
				},
			}},
		}},
		totalObs: 3,
	}
	if _, _, err := s.write(ctx, res); err != nil {
		t.Fatalf("write: %v", err)
	}
	rem, _ := store.GetRemoteByURL(ctx, "https://example.com/owner/repo")
	testutil.AssertChainIntact(t, ctx, store, rem.ID)

	obs, _ := store.ReplayObservations(ctx, rem.ID, 0, 100)
	if len(obs) != 3 {
		t.Fatalf("want 3 observations, got %d", len(obs))
	}
	if obs[1].EventType != model.EventTagDeleted {
		t.Errorf("obs[1] = %s, want tag_deleted", obs[1].EventType)
	}
	if obs[2].EventType != model.EventTagRecreated {
		t.Errorf("obs[2] = %s, want tag_recreated", obs[2].EventType)
	}
}

// --- atomicity / crash safety -----------------------------------------------

// failingStore wraps a real Store but makes the i-th AppendObservation in the
// seed's WithTx fail, to assert rollback (table empty) + a clean re-run.
type failingStore struct {
	model.Store
	failAfterObs int
}

func (f *failingStore) WithTx(ctx context.Context, fn func(ctx context.Context, tx model.Tx) error) error {
	return f.Store.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
		return fn(ctx, &failingTx{Tx: tx, fs: f})
	})
}

type failingTx struct {
	model.Tx
	fs  *failingStore
	obs int
}

func (t *failingTx) AppendObservation(ctx context.Context, o *model.Observation) (model.Seq, error) {
	t.obs++
	if t.obs > t.fs.failAfterObs {
		return 0, errBoom
	}
	return t.Tx.AppendObservation(ctx, o)
}

var errBoom = errors.New("boom: injected mid-write failure")

func TestWrite_MidWriteFailure_RollsBackThenReseeds(t *testing.T) {
	ctx := context.Background()
	real := testutil.NewTestStore(t)
	fs := &failingStore{Store: real, failAfterObs: 1} // fail on the 2nd observation
	s := newTestSeeder(t, fs)

	r := model.TaintTagOIDChanged
	res := mergeResult{
		remotes: []mergedRemote{{
			url: "https://example.com/owner/repo", normalizedURL: "https://example.com/owner/repo",
			transport: model.TransportHTTPS, taintAnyTagDeletion: true,
			tags: []mergedTag{{
				name: "v1", firstOID: mustOID(t, oidA), firstSeenNS: 1000,
				currentOID: mustOID(t, oidC), lastSeenNS: 8000, tainted: true, taintFirstNS: ip(5000),
				events: []mergedEvent{
					{eventType: model.EventTagOIDChanged, taintReason: &r, fromOID: mustOID(t, oidA), toOID: mustOID(t, oidC), detectedAtNS: 5000},
				},
			}},
		}},
		totalObs: 2,
	}
	// First write fails partway → must roll back.
	if _, _, err := s.write(ctx, res); err == nil {
		t.Fatal("expected the injected failure to surface")
	}
	n, err := real.CountAllRemotes(ctx)
	if err != nil {
		t.Fatalf("CountAllRemotes: %v", err)
	}
	if n != 0 {
		t.Fatalf("after rollback remotes must be empty, got %d", n)
	}

	// Re-run against the healthy underlying store → seeds fully.
	s2 := newTestSeeder(t, real)
	if _, _, err := s2.write(ctx, res); err != nil {
		t.Fatalf("re-run write: %v", err)
	}
	rem, err := real.GetRemoteByURL(ctx, "https://example.com/owner/repo")
	if err != nil {
		t.Fatalf("after re-seed GetRemoteByURL: %v", err)
	}
	testutil.AssertChainIntact(t, ctx, real, rem.ID)
	ref, _ := real.GetRef(ctx, rem.ID, "v1")
	if ref.ObservationCount != 2 {
		t.Errorf("observation_count = %d, want 2", ref.ObservationCount)
	}
}

// --- in-txn guard: a pre-existing remote aborts the seed (M2) ---------------

func TestWrite_InTxnGuard_AbortsOnPreexistingRemote(t *testing.T) {
	ctx := context.Background()
	store := testutil.NewTestStore(t)
	// Pre-seed a remote so the in-txn zero-rows guard must abort.
	testutil.SeedRemote(t, store, "https://preexisting.example/repo")

	s := newTestSeeder(t, store)
	res := mergeResult{
		remotes: []mergedRemote{{
			url: "https://example.com/owner/repo", normalizedURL: "https://example.com/owner/repo",
			transport: model.TransportHTTPS, taintAnyTagDeletion: true,
			tags: []mergedTag{{name: "v1", firstOID: mustOID(t, oidA), firstSeenNS: 1000, currentOID: mustOID(t, oidA), lastSeenNS: 2000}},
		}},
		totalObs: 1,
	}
	_, _, err := s.write(ctx, res)
	if err == nil {
		t.Fatal("write must abort when a remote already exists (M2 guard)")
	}
	// The pre-existing remote is untouched; no new remote was added.
	n, _ := store.CountAllRemotes(ctx)
	if n != 1 {
		t.Errorf("remotes count = %d, want 1 (only the pre-existing one)", n)
	}
	if _, err := store.GetRemoteByURL(ctx, "https://example.com/owner/repo"); err == nil {
		t.Error("the seed remote must NOT have been created")
	}
}
