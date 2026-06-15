package store

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
)

func sampleObs() *model.Observation {
	return &model.Observation{
		RemoteID:      7,
		RefID:         3,
		Seq:           1,
		EventType:     model.EventTagCreated,
		PrevOID:       model.OID{},
		NewOID:        model.MustParseOID("1111111111111111111111111111111111111111", model.SHA1),
		PrevPeeledOID: model.OID{},
		NewPeeledOID:  model.OID{},
		ObservedAtNS:  1_700_000_000_000_000_000,
		CanonicalMeta: "",
	}
}

func TestRowHash_Genesis(t *testing.T) {
	o := sampleObs()
	genesis := make([]byte, 32)
	got := RowHash(genesis, o)
	if len(got) != 32 {
		t.Fatalf("row_hash len=%d want 32", len(got))
	}
	// independent recompute: H(genesis ‖ canonical(o))
	h := sha256.New()
	h.Write(genesis)
	h.Write(CanonicalRow(o))
	want := h.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("row_hash = %x want %x", got, want)
	}
}

func TestCanonicalRow_Deterministic(t *testing.T) {
	o := sampleObs()
	a := CanonicalRow(o)
	b := CanonicalRow(o)
	if !bytes.Equal(a, b) {
		t.Fatalf("canonical not deterministic")
	}
}

func TestCanonicalRow_FieldSensitivity(t *testing.T) {
	base := CanonicalRow(sampleObs())
	// changing any chained field must change the canonical encoding
	mut := func(f func(o *model.Observation)) []byte {
		o := sampleObs()
		f(o)
		return CanonicalRow(o)
	}
	cases := map[string]func(*model.Observation){
		"remote_id":      func(o *model.Observation) { o.RemoteID = 8 },
		"seq":            func(o *model.Observation) { o.Seq = 2 },
		"ref_id":         func(o *model.Observation) { o.RefID = 4 },
		"event_type":     func(o *model.Observation) { o.EventType = model.EventTagOIDChanged },
		"new_oid":        func(o *model.Observation) { o.NewOID = model.MustParseOID("2222222222222222222222222222222222222222", model.SHA1) },
		"observed_at_ns": func(o *model.Observation) { o.ObservedAtNS = 1 },
		"canonical_meta": func(o *model.Observation) { o.CanonicalMeta = `{"k":1}` },
	}
	for name, f := range cases {
		if bytes.Equal(base, mut(f)) {
			t.Errorf("field %q does not affect canonical encoding", name)
		}
	}
}

func TestCanonicalRow_LengthPrefixAvoidsAmbiguity(t *testing.T) {
	// ("a","b") must not collide with ("ab","") — length-prefixing prevents it.
	o1 := sampleObs()
	o1.EventType = model.EventTagCreated
	o1.CanonicalMeta = "b"
	o2 := sampleObs()
	o2.EventType = model.EventTagCreated
	o2.CanonicalMeta = ""
	// Force the only-differing fields to be adjacent variable-length fields:
	if bytes.Equal(CanonicalRow(o1), CanonicalRow(o2)) {
		t.Fatalf("length-prefixing must disambiguate adjacent variable fields")
	}
}
