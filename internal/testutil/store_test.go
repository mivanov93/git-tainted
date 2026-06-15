package testutil_test

import (
	"context"
	"testing"

	"github.com/mivanov93/git-tainted/internal/testutil"
)

func TestNewTestStore_OpensMigratesAndPings(t *testing.T) {
	s := testutil.NewTestStore(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping after NewTestStore: %v", err)
	}
}

func TestAssertChainIntact_EmptyChain(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewTestStore(t)

	// Create a remote; chain_len starts at 0 (genesis).
	rid := testutil.SeedRemote(t, s, "https://github.com/org/repo.git")

	// An empty chain must be vacuously intact.
	testutil.AssertChainIntact(t, ctx, s, rid)
}
