package sync_test

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mivanov93/git-tainted/internal/git"
	"github.com/mivanov93/git-tainted/internal/lock"
	"github.com/mivanov93/git-tainted/internal/model"
	tlsync "github.com/mivanov93/git-tainted/internal/sync"
	"github.com/mivanov93/git-tainted/internal/testutil"
)

func newTestSyncer(tb testing.TB) (*tlsync.RemoteSyncer, model.Store, *testutil.FakeClock) {
	tb.Helper()
	s := testutil.NewTestStore(tb)
	clk := testutil.NewFakeClock(1_700_000_000_000_000_000)
	runner := git.NewRunnerWithProtocols("git", 30*time.Second, "http:https:ssh")
	lk := lock.NewDBLease(s, clk)
	syncer := tlsync.NewRemoteSyncer(s, runner, lk, clk, "sched-test")
	return syncer, s, clk
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestScheduler_DueRemoteGetsSync verifies that a due remote is synced within
// one tick.
func TestScheduler_DueRemoteGetsSync(t *testing.T) {
	ctx := context.Background()
	syncer, s, clk := newTestSyncer(t)

	srv := testutil.StartGitServer(t)
	const base = 1_700_000_000_000_000_000
	b := testutil.NewRepo(t, srv, "sched-repo.git", model.SHA1)
	b.Commit("main", "c1", nil, base, base)
	b.LightweightTag("v1.0", "c1")

	rid, err := s.CreateRemote(ctx, &model.Remote{
		URL:                 srv.URL("sched-repo.git"),
		NormalizedURL:       srv.URL("sched-repo.git"),
		Transport:           model.TransportHTTPS,
		Status:              model.RemoteActive,
		TaintAnyTagDeletion: true,
		SyncInterval:        1,    // 1 ns interval → always due
		StalenessBudget:     3600, // 3600 ns
		ChainHeadHash:       make([]byte, 32),
		CreatedAtNS:         clk.NowNS(),
		UpdatedAtNS:         clk.NowNS(),
	})
	if err != nil {
		t.Fatal(err)
	}

	const tick = 20 * time.Millisecond
	sched := tlsync.NewScheduler(s, syncer, clk, newLogger(), tick, 4)

	schedCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		sched.Start(schedCtx)
		close(done)
	}()

	// Poll until the chain_len advances (i.e. a sync ran) or timeout.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, length, err := s.GetChainHead(ctx, rid)
		if err == nil && length > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	<-done

	_, length, err := s.GetChainHead(ctx, rid)
	if err != nil {
		t.Fatalf("GetChainHead: %v", err)
	}
	if length == 0 {
		t.Error("expected chain_len > 0 after scheduler sync")
	}
	testutil.AssertChainIntact(t, ctx, s, rid)
}

// TestScheduler_NotDueRemoteSkipped verifies that a remote with last_ok_ns in
// the future (relative to the fake clock) is not synced.
func TestScheduler_NotDueRemoteSkipped(t *testing.T) {
	ctx := context.Background()
	syncer, s, clk := newTestSyncer(t)

	// Set last_ok_ns far into the future so the remote is never due.
	futureLastOK := clk.NowNS() + 999_000_000_000_000 // far future

	rid, err := s.CreateRemote(ctx, &model.Remote{
		URL:                 "https://example.com/not-due.git",
		NormalizedURL:       "https://example.com/not-due.git",
		Transport:           model.TransportHTTPS,
		Status:              model.RemoteActive,
		TaintAnyTagDeletion: true,
		SyncInterval:        5 * time.Minute,
		StalenessBudget:     time.Hour,
		LastOkNS:            futureLastOK, // synced recently in the "future"
		ChainHeadHash:       make([]byte, 32),
		CreatedAtNS:         clk.NowNS(),
		UpdatedAtNS:         clk.NowNS(),
	})
	if err != nil {
		t.Fatal(err)
	}

	const tick = 20 * time.Millisecond
	sched := tlsync.NewScheduler(s, syncer, clk, newLogger(), tick, 4)

	schedCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		sched.Start(schedCtx)
		close(done)
	}()

	<-done

	// Chain must still be at genesis (no sync occurred).
	_, length, err := s.GetChainHead(ctx, rid)
	if err != nil {
		t.Fatalf("GetChainHead: %v", err)
	}
	if length != 0 {
		t.Errorf("expected chain_len=0 for non-due remote, got %d", length)
	}
}

// TestScheduler_CancelDrainsInFlight verifies that cancelling the scheduler
// context waits for any in-flight sync to complete before returning.
func TestScheduler_CancelDrainsInFlight(t *testing.T) {
	ctx := context.Background()
	syncer, s, clk := newTestSyncer(t)

	srv := testutil.StartGitServer(t)
	const base = 1_700_000_000_000_000_000
	b := testutil.NewRepo(t, srv, "drain-repo.git", model.SHA1)
	b.Commit("main", "c1", nil, base, base)
	b.LightweightTag("v1.0", "c1")

	rid, err := s.CreateRemote(ctx, &model.Remote{
		URL:                 srv.URL("drain-repo.git"),
		NormalizedURL:       srv.URL("drain-repo.git"),
		Transport:           model.TransportHTTPS,
		Status:              model.RemoteActive,
		TaintAnyTagDeletion: true,
		SyncInterval:        1,
		StalenessBudget:     3600,
		ChainHeadHash:       make([]byte, 32),
		CreatedAtNS:         clk.NowNS(),
		UpdatedAtNS:         clk.NowNS(),
	})
	if err != nil {
		t.Fatal(err)
	}

	const tick = 20 * time.Millisecond
	sched := tlsync.NewScheduler(s, syncer, clk, newLogger(), tick, 4)

	schedCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		sched.Start(schedCtx)
		close(done)
	}()

	// Wait for the scheduler to have had at least one tick.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Start() must return within 5 seconds (drain completes).
	select {
	case <-done:
		// good
	case <-time.After(5 * time.Second):
		t.Fatal("scheduler Start() did not return after cancel within 5s")
	}

	// After drain, whatever state the store is in should be consistent.
	testutil.AssertChainIntact(t, ctx, s, rid)
}

// TestScheduler_ConcurrencyBounded verifies that at most concurrency syncs run
// simultaneously.
// countingSyncer is a fake sync engine that records the maximum number of
// SyncRemote calls in flight at once (and which remotes ran), so the test can
// assert the scheduler's semaphore actually bounds concurrency. It holds each
// call briefly so concurrent calls overlap observably, then marks the remote
// freshly-synced (as the real syncer does) so the scheduler rotates to the
// rest. It touches no git and no network.
type countingSyncer struct {
	store model.Store
	clk   model.Clock

	mu       sync.Mutex
	inFlight int
	maxSeen  int
	ran      map[model.RemoteID]struct{}
	hold     time.Duration
}

func (c *countingSyncer) SyncRemote(ctx context.Context, id model.RemoteID) (*tlsync.SyncResult, error) {
	c.mu.Lock()
	c.inFlight++
	if c.inFlight > c.maxSeen {
		c.maxSeen = c.inFlight
	}
	c.ran[id] = struct{}{}
	c.mu.Unlock()

	time.Sleep(c.hold) // brief overlap window so the cap is exercised, not luck

	// Mark the remote freshly-synced so it stops being due and the scheduler
	// moves on to the others (with the fixed test clock, each remote runs once).
	_ = c.store.SetRemoteHealth(ctx, id, model.RemoteActive, "", c.clk.NowNS())

	c.mu.Lock()
	c.inFlight--
	c.mu.Unlock()
	return &tlsync.SyncResult{}, nil
}

func (c *countingSyncer) snapshot() (maxSeen, distinct int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxSeen, len(c.ran)
}

// TestScheduler_ConcurrencyBounded asserts the scheduler never runs more than
// GT_SYNC_CONCURRENCY syncs at once, and still drains every due remote. It
// injects a counting fake syncer (no real git, no fixed timeout), finishes in
// ~tens of ms, and actually verifies the bound — the old version ran the real
// scheduler for a hard 5-second deadline and only checked it didn't deadlock.
func TestScheduler_ConcurrencyBounded(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewTestStore(t)
	clk := testutil.NewFakeClock(1_700_000_000_000_000_000)

	const numRemotes = 6
	const maxConcurrency = 2
	for i := range numRemotes {
		url := "https://example.test/conc-" + string(rune('a'+i)) + ".git"
		if _, err := s.CreateRemote(ctx, &model.Remote{
			URL:                 url,
			NormalizedURL:       url,
			Transport:           model.TransportHTTPS,
			Status:              model.RemoteActive,
			TaintAnyTagDeletion: true,
			SyncInterval:        1, // always due, until the first sync marks it healthy
			StalenessBudget:     3600,
			ChainHeadHash:       make([]byte, 32),
			CreatedAtNS:         clk.NowNS(),
			UpdatedAtNS:         clk.NowNS(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	cs := &countingSyncer{
		store: s,
		clk:   clk,
		ran:   make(map[model.RemoteID]struct{}),
		hold:  5 * time.Millisecond,
	}
	const tick = time.Millisecond // poll fast
	sched := tlsync.NewScheduler(s, cs, clk, newLogger(), tick, maxConcurrency)

	schedCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		sched.Start(schedCtx)
		close(done)
	}()

	// Stop the moment every remote has been synced once, bounded by a safety
	// deadline so a regression can't hang the suite.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, distinct := cs.snapshot(); distinct >= numRemotes {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			_, distinct := cs.snapshot()
			t.Fatalf("scheduler synced only %d/%d remotes before the 2s deadline", distinct, numRemotes)
		}
		time.Sleep(200 * time.Microsecond)
	}
	cancel()
	<-done

	maxSeen, distinct := cs.snapshot()
	if distinct != numRemotes {
		t.Fatalf("synced %d distinct remotes, want %d", distinct, numRemotes)
	}
	if maxSeen > maxConcurrency {
		t.Fatalf("max concurrent syncs = %d — exceeds the bound of %d", maxSeen, maxConcurrency)
	}
	if maxSeen != maxConcurrency {
		t.Fatalf("max concurrent syncs = %d — expected the cap of %d to be reached (parallelism not exercised)", maxSeen, maxConcurrency)
	}
}
