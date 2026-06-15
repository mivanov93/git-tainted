package git

import (
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
)

func TestParseLsRemote(t *testing.T) {
	const (
		tLight  = "3333333333333333333333333333333333333333" // lightweight tag → commit directly
		tAnnObj = "4444444444444444444444444444444444444444" // annotated tag-object oid
		tAnnCmt = "5555555555555555555555555555555555555555" // peeled commit of the annotated tag
		cMain   = "1111111111111111111111111111111111111111"
		cFeat   = "2222222222222222222222222222222222222222"
	)
	out := tabJoin(
		// branches must be dropped (tags only)
		[]string{cMain, "refs/heads/main"},
		[]string{cFeat, "refs/heads/feature/x"},
		// tags kept
		[]string{tLight, "refs/tags/v1.0-light"},
		[]string{tAnnObj, "refs/tags/v2.0"},
		[]string{tAnnCmt, "refs/tags/v2.0^{}"},
		// non-heads/tags namespaces must be dropped:
		[]string{cMain, "HEAD"},
		[]string{cFeat, "refs/pull/7/head"},
		[]string{cMain, "refs/replace/" + cMain},
		[]string{cFeat, "refs/notes/commits"},
	)

	got, err := ParseLsRemote([]byte(out), model.SHA1)
	if err != nil {
		t.Fatalf("ParseLsRemote err = %v", err)
	}

	// Only tag refs should be returned (branches dropped).
	want := []model.LsRemoteRef{
		{Name: "v1.0-light", OID: model.MustParseOID(tLight, model.SHA1)},
		{
			Name:           "v2.0",
			OID:            model.MustParseOID(tAnnObj, model.SHA1),
			PeeledOID:      model.MustParseOID(tAnnCmt, model.SHA1),
			IsAnnotatedTag: true,
		},
	}
	assertRefsEqual(t, got, want)
}

func TestParseLsRemote_RejectsBadOIDWidth(t *testing.T) {
	// sha256 expected but a 40-hex (sha1-width) oid present → reject.
	out := tabJoin([]string{"abcdef0000000000000000000000000000000000", "refs/tags/v1.0"})
	if _, err := ParseLsRemote([]byte(out), model.SHA256); err == nil {
		t.Fatalf("expected error for oid width mismatch, got nil")
	}
}

func TestParseLsRemote_Sha256Width(t *testing.T) {
	c := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	out := tabJoin([]string{c, "refs/tags/v1.0"})
	got, err := ParseLsRemote([]byte(out), model.SHA256)
	if err != nil {
		t.Fatalf("ParseLsRemote err = %v", err)
	}
	if len(got) != 1 || got[0].OID.Hex() != c || got[0].OID.Algo != model.SHA256 {
		t.Fatalf("sha256 parse wrong: %+v", got)
	}
}

func TestParseLsRemote_PeeledWithoutBaseIsError(t *testing.T) {
	// a ^{} peeled line with no preceding tag-object line is malformed.
	out := tabJoin([]string{"5555555555555555555555555555555555555555", "refs/tags/v2.0^{}"})
	if _, err := ParseLsRemote([]byte(out), model.SHA1); err == nil {
		t.Fatalf("expected error for dangling peeled line, got nil")
	}
}

// tabJoin renders ls-remote output lines: "<oid>\t<ref>\n".
func tabJoin(rows ...[]string) string {
	var b []byte
	for _, r := range rows {
		b = append(b, r[0]...)
		b = append(b, '\t')
		b = append(b, r[1]...)
		b = append(b, '\n')
	}
	return string(b)
}

func assertRefsEqual(t *testing.T, got, want []model.LsRemoteRef) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("len(got)=%d want %d\ngot=%+v", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Name != w.Name || g.IsAnnotatedTag != w.IsAnnotatedTag {
			t.Errorf("row %d meta got %+v want %+v", i, g, w)
		}
		if !g.OID.Equal(w.OID) {
			t.Errorf("row %d oid got %s want %s", i, g.OID.Hex(), w.OID.Hex())
		}
		if !g.PeeledOID.Equal(w.PeeledOID) {
			t.Errorf("row %d peeled got %s want %s", i, g.PeeledOID.Hex(), w.PeeledOID.Hex())
		}
	}
}
