package model

import "context"

// LsRemoteRef is one parsed ls-remote line. For annotated tags both the
// tag-object oid (OID) and the peeled ^{} commit (PeeledOID) are present in
// one call. Namespaces outside refs/tags/* are dropped by the parser before
// this type is produced.
type LsRemoteRef struct {
	Name           RefName // short name (prefix stripped)
	OID            OID
	PeeledOID      OID  // zero unless annotated tag
	IsAnnotatedTag bool
}

// MaterializedAuth carries resolved credentials for a git operation.
type MaterializedAuth struct {
	GitConfigGlobal string
	SSHCommand      string
	EnvOverlay      []string
}

// GitRunner wraps the system git binary with all hardening (no shell,
// --no-replace-objects, env preamble, protocol allowlist, per-call timeout).
// Only ls-remote is used — no object fetch ever.
type GitRunner interface {
	// LsRemote lists refs+oids+peeled tags with zero object transfer.
	// It restricts parsing to refs/tags/* only.
	LsRemote(ctx context.Context, url string, auth *MaterializedAuth) ([]LsRemoteRef, error)
}
