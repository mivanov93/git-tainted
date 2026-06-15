package store_test

import (
	"context"
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/testutil"
)

func TestAppendObservation_AdvancesChainSameTxn(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewTestStore(t)

	rid := testutil.SeedRemote(t, s, "https://example.com/r.git")
	ref := &model.Ref{
		RemoteID: rid,
		TagName:  "v1.0.0",
		CurrentOID: model.MustParseOID("1111111111111111111111111111111111111111", model.SHA1),
	}

	oids := []string{
		"1111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222",
		"3333333333333333333333333333333333333333",
	}
	for i, hexOID := range oids {
		err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
			if err := tx.UpsertRefProjection(ctx, ref); err != nil {
				return err
			}
			// WriteSync must precede AppendObservation (sync_id NOT NULL).
			if _, err := tx.WriteSync(ctx, &model.Sync{
				RemoteID: rid, Trigger: model.TriggerManual,
				StartedNS: int64(i + 1), FinishedNS: int64(i + 1),
				Status: model.SyncOk,
			}); err != nil {
				return err
			}
			ev := model.EventTagOIDChanged
			if i == 0 {
				ev = model.EventTagCreated
			}
			o := &model.Observation{
				RemoteID:     rid,
				RefID:        ref.ID,
				EventType:    ev,
				NewOID:       model.MustParseOID(hexOID, model.SHA1),
				ObservedAtNS: int64(1_700_000_000_000_000_000 + i),
			}
			seq, err := tx.AppendObservation(ctx, o)
			if err != nil {
				return err
			}
			if int64(seq) != int64(i+1) {
				t.Errorf("append %d seq=%d want %d", i, seq, i+1)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	head, length, err := s.GetChainHead(ctx, rid)
	if err != nil {
		t.Fatalf("GetChainHead: %v", err)
	}
	if length != 3 {
		t.Fatalf("chain_len=%d want 3", length)
	}
	if len(head) != 32 {
		t.Fatalf("chain_head len=%d want 32", len(head))
	}
	// full independent replay must reproduce head & length
	testutil.AssertChainIntact(t, ctx, s, rid)
}
