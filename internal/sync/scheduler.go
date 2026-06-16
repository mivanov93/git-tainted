// Package sync scheduler.go — the per-remote polling scheduler (§12).
// It selects due remotes every SchedulerTick, acquires the per-remote Lock
// (preventing overlap with a concurrent TriggerSync), and runs SyncRemote
// bounded by a semaphore of size SyncConcurrency.
package sync

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/mivanov93/git-tainted/internal/model"
)

// remoteSyncer is the scheduler's view of the sync engine: drive a single
// remote's sync to completion. *RemoteSyncer satisfies it; tests inject a fake
// to observe that concurrency stays bounded — without spinning up real git.
type remoteSyncer interface {
	SyncRemote(ctx context.Context, remoteID model.RemoteID) (*SyncResult, error)
}

// Scheduler polls the Store for due remotes and drives the sync engine.
type Scheduler struct {
	store  syncStore
	syncer remoteSyncer
	clk    model.Clock
	log    *slog.Logger

	tick        time.Duration
	concurrency int
}

// NewScheduler constructs a Scheduler.
// tick is the polling interval; concurrency is the max parallel SyncRemote
// calls in flight.
func NewScheduler(store syncStore, syncer remoteSyncer, clk model.Clock, log *slog.Logger, tick time.Duration, concurrency int) *Scheduler {
	return &Scheduler{
		store:       store,
		syncer:      syncer,
		clk:         clk,
		log:         log,
		tick:        tick,
		concurrency: concurrency,
	}
}

// Start runs the polling loop until ctx is cancelled, then drains all
// in-flight syncs before returning. It blocks the caller; run it in a goroutine.
func (sc *Scheduler) Start(ctx context.Context) {
	sem := make(chan struct{}, sc.concurrency)
	var wg sync.WaitGroup

	ticker := time.NewTicker(sc.tick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Drain all in-flight syncs before returning.
			wg.Wait()
			return
		case <-ticker.C:
			sc.poll(ctx, sem, &wg)
		}
	}
}

// poll selects due remotes and spawns goroutines (bounded by the semaphore).
func (sc *Scheduler) poll(ctx context.Context, sem chan struct{}, wg *sync.WaitGroup) {
	now := sc.clk.NowNS()
	remotes, err := sc.store.SelectDueRemotes(ctx, now, sc.concurrency*2)
	if err != nil {
		sc.log.Error("scheduler: SelectDueRemotes failed", "err", err)
		return
	}

	for _, r := range remotes {
		if ctx.Err() != nil {
			return
		}
		rid := r.ID
		// Non-blocking acquire of semaphore slot — skip if already at capacity.
		select {
		case sem <- struct{}{}:
		default:
			sc.log.Debug("scheduler: concurrency cap reached, skipping remote", "remote_id", rid)
			continue
		}
		wg.Add(1)
		go func(remoteID model.RemoteID) { //nolint:gosec // G118: intentional background sync; scheduler ctx is only for tick cancellation
			defer wg.Done()
			defer func() { <-sem }()
			if _, err := sc.syncer.SyncRemote(context.Background(), remoteID); err != nil {
				sc.log.Error("scheduler: SyncRemote failed", "remote_id", remoteID, "err", err)
			}
		}(rid)
	}
}
