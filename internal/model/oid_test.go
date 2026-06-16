package model

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAlgoWidths(t *testing.T) {
	if SHA1.RawLen() != 20 || SHA1.HexLen() != 40 {
		t.Errorf("sha1 widths wrong: raw=%d hex=%d", SHA1.RawLen(), SHA1.HexLen())
	}
	if SHA256.RawLen() != 32 || SHA256.HexLen() != 64 {
		t.Errorf("sha256 widths wrong: raw=%d hex=%d", SHA256.RawLen(), SHA256.HexLen())
	}
	if HashAlgo("md5").RawLen() != 0 || HashAlgo("md5").Valid() {
		t.Errorf("unknown algo must be 0-width and invalid")
	}
}

func TestParseOID(t *testing.T) {
	const sha1Hex = "0123456789abcdef0123456789abcdef01234567"                           // 40
	const sha256Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64

	tests := []struct {
		name    string
		hex     string
		algo    HashAlgo
		wantErr bool
	}{
		{"valid sha1", sha1Hex, SHA1, false},
		{"valid sha256", sha256Hex, SHA256, false},
		{"abbreviation rejected", sha1Hex[:7], SHA1, true},
		{"uppercase rejected", strings.ToUpper(sha1Hex), SHA1, true},
		{"wrong width for algo", sha1Hex, SHA256, true},
		{"non-hex char rejected", "z123456789abcdef0123456789abcdef01234567", SHA1, true},
		{"unknown algo rejected", sha1Hex, HashAlgo("md5"), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, err := ParseOID(tc.hex, tc.algo)
			if tc.wantErr {
				if !errors.Is(err, ErrBadOID) {
					t.Fatalf("err = %v, want ErrBadOID", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if o.Hex() != tc.hex {
				t.Errorf("round-trip Hex = %q, want %q", o.Hex(), tc.hex)
			}
			if o.Algo != tc.algo {
				t.Errorf("algo = %q, want %q", o.Algo, tc.algo)
			}
			if o.IsZero() {
				t.Errorf("parsed oid must not be zero")
			}
		})
	}
}

func TestOIDEqualAndZero(t *testing.T) {
	a := MustParseOID("0123456789abcdef0123456789abcdef01234567", SHA1)
	b := MustParseOID("0123456789abcdef0123456789abcdef01234567", SHA1)
	c := MustParseOID("ffffffffffffffffffffffffffffffffffffffff", SHA1)
	if !a.Equal(b) {
		t.Errorf("equal oids must compare Equal")
	}
	if a.Equal(c) {
		t.Errorf("different oids must not compare Equal")
	}
	var z OID
	if !z.IsZero() {
		t.Errorf("zero-value OID must be IsZero")
	}
	if a.Equal(z) {
		t.Errorf("nonzero must not equal zero")
	}
	// Equal is algo-sensitive: same raw bytes, different algo must not be Equal.
	// (Constructed directly — OIDFromRaw now infers the algo from width, so it
	// can't produce a mislabelled oid.)
	d := OID{Raw: a.Raw, Algo: SHA256}
	if a.Equal(d) {
		t.Errorf("same raw, different algo must not be Equal")
	}
}

func TestOIDFromRawInfersAlgo(t *testing.T) {
	if got := OIDFromRaw(make([]byte, 20)).Algo; got != SHA1 {
		t.Errorf("20-byte raw → algo %q, want sha1", got)
	}
	if got := OIDFromRaw(make([]byte, 32)).Algo; got != SHA256 {
		t.Errorf("32-byte raw → algo %q, want sha256", got)
	}
	if got := OIDFromRaw(make([]byte, 16)).Algo; got != "" {
		t.Errorf("unknown-width raw → algo %q, want empty", got)
	}
	// A sha256 raw round-trips with the right algo, so OID.Equal holds across a
	// store boundary — regression for the sha1-hard-coded decode that false-tainted
	// every unchanged sha256 tag.
	raw := make([]byte, 32)
	raw[0] = 0xab
	if want := (OID{Raw: raw, Algo: SHA256}); !OIDFromRaw(raw).Equal(want) {
		t.Errorf("OIDFromRaw(32-byte raw) must Equal the same bytes labelled sha256")
	}
}

func TestMustParseOIDPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Errorf("MustParseOID must panic on bad input")
		}
	}()
	MustParseOID("nope", SHA1)
}
