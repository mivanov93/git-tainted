package store

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/mivanov93/git-tainted/internal/model"
)

// chainHashLen is the SHA-256 digest size; genesis prev_hash is this many zero bytes.
const chainHashLen = 32

// writeField appends a length-prefixed field: uint64(len) big-endian ‖ bytes.
// Length-prefixing makes the field concatenation injective so distinct field
// tuples can never produce the same canonical byte string (§13).
func writeField(buf []byte, b []byte) []byte {
	var lp [8]byte
	binary.BigEndian.PutUint64(lp[:], uint64(len(b)))
	buf = append(buf, lp[:]...)
	return append(buf, b...)
}

// writeInt appends an int64 field as a length-prefixed 8-byte big-endian value.
func writeInt(buf []byte, v int64) []byte {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], uint64(v)) //nolint:gosec // deliberate bit-pattern cast for chain encoding
	return writeField(buf, x[:])
}

// CanonicalRow is the deterministic, length-prefixed encoding of an
// observation's chained fields in the FIXED order mandated by §13:
// remote_id, seq, ref_id, event_type, prev_oid, new_oid, prev_peeled_oid,
// new_peeled_oid, observed_at_ns, canonical_meta. Reproducible by an
// independent auditor from the same field values.
func CanonicalRow(o *model.Observation) []byte {
	buf := make([]byte, 0, 256)
	buf = writeInt(buf, int64(o.RemoteID))
	buf = writeInt(buf, int64(o.Seq))
	buf = writeInt(buf, int64(o.RefID))
	buf = writeField(buf, []byte(o.EventType))
	buf = writeField(buf, o.PrevOID.Raw)
	buf = writeField(buf, o.NewOID.Raw)
	buf = writeField(buf, o.PrevPeeledOID.Raw)
	buf = writeField(buf, o.NewPeeledOID.Raw)
	buf = writeInt(buf, o.ObservedAtNS)
	buf = writeField(buf, []byte(o.CanonicalMeta))
	return buf
}

// RowHash computes row_hash = SHA256(prev_hash ‖ canonical(row)) (§13).
// prevHash MUST be 32 bytes (genesis = 32 zero bytes).
func RowHash(prevHash []byte, o *model.Observation) []byte {
	h := sha256.New()
	h.Write(prevHash)
	h.Write(CanonicalRow(o))
	return h.Sum(nil)
}

