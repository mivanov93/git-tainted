package sqlite

import (
	"context"
	"strings"
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
)

// TestGetRef_SHA256OidAlgoRoundTrip is a regression test for the oid hash-algo
// decode bug: the store decoded every oid as sha1, so a sha256 ref read back from
// the DB was labelled sha1. Because model.OID.Equal compares algo (and the sync's
// ClassifyTag gates "unchanged" on now.OID.Equal(prev.CurrentOID)), an UNCHANGED
// sha256 tag mis-compared on every re-sync → a spurious taint on the whole fleet
// of sha256 remotes (the algorithm the README recommends).
//
// Before the fix this fails (Algo == sha1, Equal == false). After, the algo is
// inferred from the raw width and the round-trip is faithful.
func TestGetRef_SHA256OidAlgoRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	rid := seedRemote(t, s, "https://github.com/org/sha256repo.git")

	// A full-width sha256 oid: 64 hex chars = 32 raw bytes.
	oid := model.MustParseOID(strings.Repeat("ab", 32), model.SHA256)

	ref := &model.Ref{
		RemoteID:         rid,
		TagName:          "v1.0",
		CurrentOID:       oid,
		CurrentPeeledOID: oid,
		FirstOID:         oid,
		FirstSeenNS:      1,
		LastSeenNS:       1,
		LastChangedNS:    1,
		ObservationCount: 1,
	}
	if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
		return tx.UpsertRefProjection(ctx, ref)
	}); err != nil {
		t.Fatalf("upsert ref: %v", err)
	}

	got, err := s.GetRef(ctx, rid, "v1.0")
	if err != nil {
		t.Fatalf("GetRef: %v", err)
	}
	if got.CurrentOID.Algo != model.SHA256 {
		t.Errorf("read-back CurrentOID.Algo = %q, want %q (store decode mislabels the hash algo)", got.CurrentOID.Algo, model.SHA256)
	}
	if !got.CurrentOID.Equal(oid) {
		t.Errorf("read-back sha256 oid does not Equal the original — ClassifyTag would false-taint every unchanged sha256 tag (read-back Algo=%q)", got.CurrentOID.Algo)
	}
}
