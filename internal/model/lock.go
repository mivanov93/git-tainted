package model

import (
	"context"
	"time"
)

// Lease is a held per-remote writer lease bound to the chain head it was
// acquired against. Release performs the chain_head CAS (design spec §9.1,
// §5.3 Lock seam).
type Lease struct {
	RemoteID         RemoteID
	Holder           string // instance id
	AcquiredAtNS     int64
	ExpiresAtNS      int64
	ChainHeadAtLease []byte // 32-byte chain_head observed at acquisition (CAS witness)
}

// Lock elects one writer per remote chain across instances (DB lease +
// chain_head CAS), degrading to a process-local mutex for single-instance.
type Lock interface {
	// AcquireRemoteLease wins (or renews) the exclusive writer lease for a
	// remote's chain. ttl bounds the lease. It records the current
	// chain_head as the CAS witness in the returned Lease. Returns
	// ErrLeaseHeld if another live holder owns it.
	AcquireRemoteLease(ctx context.Context, remoteID RemoteID, holder string, ttl time.Duration) (*Lease, error)

	// Release relinquishes the lease, performing the chain_head CAS: the
	// release (and the caller's committed observations) are valid only if the
	// stored chain_head still equals lease.ChainHeadAtLease advanced by exactly
	// the caller's appended rows. Returns ErrChainCAS if another writer mutated
	// the chain (the caller must roll back / retry).
	Release(ctx context.Context, lease *Lease, newChainHead []byte, newChainLen int64) error
}
