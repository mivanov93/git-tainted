package model

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

// HashAlgo is a repository's object format. Width: sha1=20B, sha256=32B raw.
type HashAlgo string

const (
	SHA1   HashAlgo = "sha1"
	SHA256 HashAlgo = "sha256"
)

// RawLen returns the raw oid byte length for this algo (20 or 32), or 0 if unknown.
func (h HashAlgo) RawLen() int {
	switch h {
	case SHA1:
		return 20
	case SHA256:
		return 32
	default:
		return 0
	}
}

// HexLen returns 40 (sha1) or 64 (sha256), or 0 if unknown.
func (h HashAlgo) HexLen() int { return h.RawLen() * 2 }

// Valid reports whether h is a known algorithm.
func (h HashAlgo) Valid() bool { return h == SHA1 || h == SHA256 }

// OID is a raw git object id plus its hash algorithm. Raw is the canonical
// storage form (BLOB); Hex is for display/JSON/argv-free comparison. An OID is
// the integrity anchor — never construct one from a user-supplied abbreviation;
// ParseOID enforces exact width (design spec §7, §12.2).
type OID struct {
	Raw  []byte
	Algo HashAlgo
}

// Hex returns the lowercase hex encoding of the raw oid.
func (o OID) Hex() string { return hex.EncodeToString(o.Raw) }

// IsZero reports whether the oid is unset (nil/empty raw).
func (o OID) IsZero() bool { return len(o.Raw) == 0 }

// Equal reports byte-and-algo equality in constant time.
func (o OID) Equal(other OID) bool {
	return o.Algo == other.Algo && subtleConstEq(o.Raw, other.Raw)
}

// ErrBadOID is returned by ParseOID for any malformed oid input.
var ErrBadOID = errors.New("model: malformed oid")

// ParseOID validates a full, lowercase 40/64-hex string against algo and returns
// the raw OID. It REJECTS abbreviations, uppercase, and width mismatch
// (ErrBadOID). This is the only sanctioned oid constructor from text; callers
// must never pass an unvalidated hash onward to git.
func ParseOID(hexStr string, algo HashAlgo) (OID, error) {
	if !algo.Valid() || len(hexStr) != algo.HexLen() {
		return OID{}, fmt.Errorf("%w: want %d lowercase hex chars for %s, got %d", ErrBadOID, algo.HexLen(), algo, len(hexStr))
	}
	for i := 0; i < len(hexStr); i++ {
		c := hexStr[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return OID{}, fmt.Errorf("%w: non-lowercase-hex byte at %d", ErrBadOID, i)
		}
	}
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return OID{}, fmt.Errorf("%w: %w", ErrBadOID, err)
	}
	return OID{Raw: raw, Algo: algo}, nil
}

// MustParseOID is ParseOID for tests/constants; panics on error.
func MustParseOID(hexStr string, algo HashAlgo) OID {
	o, err := ParseOID(hexStr, algo)
	if err != nil {
		panic(err)
	}
	return o
}

// OIDFromRaw wraps already-validated raw bytes (e.g. read from the Store).
func OIDFromRaw(raw []byte, algo HashAlgo) OID { return OID{Raw: raw, Algo: algo} }

// subtleConstEq is a constant-time byte-slice compare.
func subtleConstEq(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
