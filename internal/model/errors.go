package model

import "errors"

// Sentinel errors. Implementations MUST wrap these (fmt.Errorf("...: %w", Err…));
// callers branch only on these via errors.Is. (ErrBadOID lives in oid.go.)
var (
	ErrNotFound  = errors.New("model: not found")
	ErrConflict  = errors.New("model: unique conflict")       // normalized_url dup
	ErrChainCAS  = errors.New("model: chain_head CAS failed") // lost the writer race
	ErrLeaseHeld = errors.New("model: remote lease held by another holder")
	ErrLeaseLost = errors.New("model: remote lease lost / expired")
	ErrBadURL    = errors.New("model: url failed validation/normalization")
)
