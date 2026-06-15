// Package lock implements the Lock seam — DB-backed per-remote writer lease
// with chain_head CAS release (§5.3, §9.1).
package lock

import (
	"context"
	"errors"
	"fmt"

	"github.com/mivanov93/git-tainted/internal/model"
)

type dbLease struct {
	s   model.LeaseStore
	clk model.Clock
}

// NewDBLease constructs the DB-backed per-remote-chain Lock (§5.3).
// s must implement model.LeaseStore (satisfied by the sqliteStore returned
// from store.Open, and by model.Store which embeds LeaseStore).
func NewDBLease(s model.LeaseStore, clk model.Clock) model.Lock {
	return &dbLease{s: s, clk: clk}
}

// AcquireRemoteLease wins an exclusive lease for remoteID. ttlNS is the
// lease duration in nanoseconds. Returns ErrLeaseHeld when a live lease
// already exists for a different holder.
func (d *dbLease) AcquireRemoteLease(ctx context.Context, remoteID model.RemoteID, holder string, ttlNS int64) (*model.Lease, error) {
	now := d.clk.NowNS()
	expires := now + ttlNS
	ok, head, err := d.s.TryAcquireLease(ctx, remoteID, holder, now, expires)
	if err != nil {
		return nil, fmt.Errorf("acquire lease: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("remote %d: %w", remoteID, model.ErrLeaseHeld)
	}
	return &model.Lease{
		RemoteID:         remoteID,
		Holder:           holder,
		AcquiredAtNS:     now,
		ExpiresAtNS:      expires,
		ChainHeadAtLease: head,
	}, nil
}

// Release deletes the lease and advances chain_head from
// lease.ChainHeadAtLease to newChainHead (CAS). Returns ErrChainCAS when the
// chain was advanced by a concurrent writer between Acquire and Release.
func (d *dbLease) Release(ctx context.Context, lease *model.Lease, newChainHead []byte, newChainLen int64) error {
	if lease == nil {
		return errors.New("lock: nil lease")
	}
	err := d.s.ReleaseLeaseCAS(ctx, lease.RemoteID, lease.Holder, lease.ChainHeadAtLease, newChainHead, newChainLen)
	if err != nil {
		return fmt.Errorf("release lease: %w", err)
	}
	return nil
}
