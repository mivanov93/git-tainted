// Package model domain.go — the domain structs that mirror §9 columns and
// the API surface. All timestamps are int64 unix-nanoseconds (field suffix NS).
// All oids are raw bytes wrapped in OID. Pointers are used for genuinely optional
// fields (nullable columns, detected-on-first-sync values).
package model

// RemoteStatus is the last-known health/lifecycle status of a remote.
type RemoteStatus string

const (
	RemoteActive   RemoteStatus = "active"
	RemoteDegraded RemoteStatus = "degraded"
	RemotePaused   RemoteStatus = "paused"
)

// Remote is the top-level tracked entity — a git remote URL we poll for tags.
type Remote struct {
	ID                  RemoteID
	URL                 string
	NormalizedURL       string
	Transport           Transport
	SyncIntervalNS      int64
	StalenessBudgetNS   int64
	TaintAnyTagDeletion bool // default true
	HashAlgo            *HashAlgo
	Status              RemoteStatus
	LastOkNS            int64
	LastErr             string
	ConsecutiveFailures int
	ChainHeadHash       []byte // 32 bytes; genesis = 32 zero bytes
	ChainLen            int64
	RemovedAtNS         *int64
	CreatedAtNS         int64
	UpdatedAtNS         int64
}

// Ref is the per-remote current-state projection of a tag.
// Tags only: no branches, no DAG fields.
type Ref struct {
	ID               RefID
	RemoteID         RemoteID
	TagName          string
	CurrentOID       OID // tag-object oid for annotated tags; commit oid for lightweight
	CurrentPeeledOID OID // peeled commit; zero for lightweight
	IsAnnotatedTag   bool
	FirstOID         OID
	FirstSeenNS      int64
	LastSeenNS       int64
	LastChangedNS    int64
	Deleted          bool
	Tainted          bool
	TaintFirstNS     *int64
	ObservationCount int64
}

// ObservationProof is the ledger pointer attesting a ref's recorded state: the
// {remote, seq, row_hash} of its most-recent (highest-seq) observation.
type ObservationProof struct {
	RemoteID RemoteID
	Seq      Seq
	RowHash  []byte // 32-byte SHA-256 chain row hash
}

// Observation is one append-only entry in a per-remote hash-chained ledger.
type Observation struct {
	ID            int64
	RemoteID      RemoteID
	RefID         RefID
	SyncID        SyncID
	Seq           Seq
	EventType     ObservationEventType
	PrevOID       OID
	NewOID        OID
	PrevPeeledOID OID
	NewPeeledOID  OID
	ObservedAtNS  int64
	PrevHash      []byte // 32 bytes
	RowHash       []byte // 32 bytes = H(prev_hash || canonical(row))
	CanonicalMeta string // nullable JSON; empty = NULL
}

// TaintEvent is one immutable row in the taint spine.
type TaintEvent struct {
	ID            int64
	RemoteID      RemoteID
	RefID         RefID
	Reason        TaintReason
	ObservationID *int64
	FromOID       OID
	ToOID         OID
	DetectedAtNS  int64
	AckedAtNS     *int64
	AckedBy       string
	AckNote       string
	Detail        string
}

// SyncStatus is the outcome of a sync run.
type SyncStatus string

const (
	SyncOk      SyncStatus = "ok"
	SyncPartial SyncStatus = "partial"
	SyncFailed  SyncStatus = "failed"
)

// SyncTrigger is what triggered a sync run.
type SyncTrigger string

const (
	TriggerRegister  SyncTrigger = "register"
	TriggerScheduled SyncTrigger = "scheduled"
	TriggerManual    SyncTrigger = "manual"
)

// Sync is one row in the run-audit log.
type Sync struct {
	ID              SyncID
	RemoteID        RemoteID
	Trigger         SyncTrigger
	StartedNS       int64
	FinishedNS      int64
	Status          SyncStatus
	TagsSeen        int
	TagsChanged     int
	Error           string
	ChainHeadBefore []byte // 32 bytes
	ChainHeadAfter  []byte // 32 bytes
}
