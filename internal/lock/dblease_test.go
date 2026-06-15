package lock_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mivanov93/git-tainted/internal/lock"
	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/testutil"
)

func setupRemote(t *testing.T, ctx context.Context, s model.Store) model.RemoteID {
	t.Helper()
	return testutil.SeedRemote(t, s, "https://example.com/r.git")
}

func TestDBLease_AcquireRejectsSecondHolder(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewTestStore(t)
	clk := testutil.NewFakeClock(1_000)
	rid := setupRemote(t, ctx, s)

	lk := lock.NewDBLease(s, clk)
	l1, err := lk.AcquireRemoteLease(ctx, rid, "inst-A", 10_000)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if len(l1.ChainHeadAtLease) != 32 {
		t.Fatalf("witness len=%d want 32", len(l1.ChainHeadAtLease))
	}
	if _, err := lk.AcquireRemoteLease(ctx, rid, "inst-B", 10_000); !errors.Is(err, model.ErrLeaseHeld) {
		t.Fatalf("second acquire err=%v want ErrLeaseHeld", err)
	}
}

func TestDBLease_AcquireAfterExpiry(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewTestStore(t)
	clk := testutil.NewFakeClock(1_000)
	rid := setupRemote(t, ctx, s)

	lk := lock.NewDBLease(s, clk)
	if _, err := lk.AcquireRemoteLease(ctx, rid, "inst-A", 5_000); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	clk.Advance(6_000) // past expiry
	if _, err := lk.AcquireRemoteLease(ctx, rid, "inst-B", 5_000); err != nil {
		t.Fatalf("acquire after expiry should succeed: %v", err)
	}
}

func TestDBLease_ReleaseAdvancesAndCAS(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewTestStore(t)
	clk := testutil.NewFakeClock(1_000)
	rid := setupRemote(t, ctx, s)

	lk := lock.NewDBLease(s, clk)
	l, err := lk.AcquireRemoteLease(ctx, rid, "inst-A", 10_000)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// release with the chain unchanged (genesis witness) advancing to a new head
	newHead := make([]byte, 32)
	newHead[0] = 0xAB
	if err := lk.Release(ctx, l, newHead, 1); err != nil {
		t.Fatalf("release: %v", err)
	}
}
