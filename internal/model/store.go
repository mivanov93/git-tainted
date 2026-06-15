package model

import (
	"context"
	"io"
)

// Tx is a write transaction scope used by the sync write path.
// One transaction atomically appends observations, upserts refs projection,
// writes the syncs row, advances chain_head_hash/chain_len, and appends
// taint_events — so a crash can never tear the chain.
type Tx interface {
	AppendObservation(ctx context.Context, o *Observation) (Seq, error)
	UpsertRefProjection(ctx context.Context, ref *Ref) error
	WriteSync(ctx context.Context, s *Sync) (SyncID, error)
	AdvanceChainHead(ctx context.Context, remoteID RemoteID, newHead []byte, newLen int64) error
	// AppendTaintEvent appends an immutable taint_events row inside the same txn.
	// Idempotent on the unique key.
	AppendTaintEvent(ctx context.Context, e *TaintEvent) (int64, error)
}

// RemoteStore: remote CRUD + scheduler selection + health/state.
type RemoteStore interface {
	CreateRemote(ctx context.Context, r *Remote) (RemoteID, error) // ErrConflict on dup normalized_url
	GetRemote(ctx context.Context, id RemoteID) (*Remote, error)
	GetRemoteByURL(ctx context.Context, normalizedURL string) (*Remote, error)
	ListRemotes(ctx context.Context, limit int, cursor int64) ([]Remote, int64, error)
	UpdateRemote(ctx context.Context, r *Remote) error
	SoftDeleteRemote(ctx context.Context, id RemoteID, atNS int64) error
	SelectDueRemotes(ctx context.Context, nowNS int64, limit int) ([]Remote, error)
	SetRemoteHealth(ctx context.Context, id RemoteID, status RemoteStatus, lastErr string, lastOkNS int64) error
}

// RefStore: per-remote tag projection reads/writes.
type RefStore interface {
	GetRef(ctx context.Context, remoteID RemoteID, tagName string) (*Ref, error)
	ListTags(ctx context.Context, remoteID RemoteID) ([]Ref, error)
	SetRefTaint(ctx context.Context, refID RefID, firstNS int64) error // sticky; idempotent
}

// ObservationStore: append-only chain reads + audit replay.
type ObservationStore interface {
	GetChainHead(ctx context.Context, remoteID RemoteID) (head []byte, length int64, err error)
	ReplayObservations(ctx context.Context, remoteID RemoteID, fromSeq Seq, limit int) ([]Observation, error)
	// LatestObservationForRef returns the most-recent observation (highest seq) for
	// a tag ref — the ledger row attesting its current oid. ErrNotFound if none.
	LatestObservationForRef(ctx context.Context, refID RefID) (*ObservationProof, error)
}

// TaintStore: immutable taint spine + ack annotation.
type TaintStore interface {
	AppendTaintEvent(ctx context.Context, e *TaintEvent) (int64, error)
	ListTaintEvents(ctx context.Context, remoteID RemoteID, limit int, cursor int64) ([]TaintEvent, int64, error)
	AckTaintEvent(ctx context.Context, id int64, by, note string, atNS int64) error
}

// SyncStore: sync run audit.
type SyncStore interface {
	ListSyncs(ctx context.Context, remoteID RemoteID, limit int, cursor int64) ([]Sync, int64, error)
}

// LeaseStore is the narrow persistence surface for the DB-backed lock seam.
type LeaseStore interface {
	TryAcquireLease(ctx context.Context, remoteID RemoteID, holder string, nowNS, expiresNS int64) (ok bool, chainHead []byte, err error)
	ReleaseLeaseCAS(ctx context.Context, remoteID RemoteID, holder string, witness, newHead []byte, newLen int64) error
}

// Store is the full persistence seam: the union of role-interfaces plus
// transaction orchestration and lifecycle.
type Store interface {
	RemoteStore
	RefStore
	ObservationStore
	TaintStore
	SyncStore
	LeaseStore

	WithTx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error
	Migrate(ctx context.Context) error
	Ping(ctx context.Context) error
	io.Closer
}
