package model

// RemoteID identifies a remote.
type RemoteID int64

// Identity newtypes (§9 surrogate keys; Seq = per-remote monotonic observation sequence).
type RefID int64
type SyncID int64
type Seq int64

// RefName is the SHORT tag name (prefix stripped: refs/tags/<X> → <X>).
// Fully-qualified names are rejected at the API door (§7).
type RefName = string
