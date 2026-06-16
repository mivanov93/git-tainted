// Package testutil provides shared test infrastructure: an in-temp-file
// SQLite Store with migrations applied (NewTestStore), and a chain-integrity
// assertion helper (AssertChainIntact) that verifies the per-remote hash chain.
package testutil

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"testing"
	"time"

	"github.com/mivanov93/git-tainted/db"
	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/store/sqlite"
)

// NewTestStore opens an in-temp-file modernc SQLite Store with the embedded
// migrations applied. The temp file and the Store are closed and removed via
// t.Cleanup.
func NewTestStore(tb testing.TB) model.Store {
	tb.Helper()
	f, err := os.CreateTemp("", "git-tainted-testutil-*.db")
	if err != nil {
		tb.Fatalf("testutil.NewTestStore: create temp db: %v", err)
	}
	if err := f.Close(); err != nil {
		tb.Fatalf("testutil.NewTestStore: close temp file: %v", err)
	}
	tb.Cleanup(func() { _ = os.Remove(f.Name()) })

	// sqlite.Open migrates from the embedded SQLite migration FS.
	s, err := sqlite.Open(f.Name(), db.SQLiteMigrations)
	if err != nil {
		tb.Fatalf("testutil.NewTestStore: open: %v", err)
	}
	tb.Cleanup(func() { _ = s.Close() })
	return s
}

// SeedRemote inserts a minimal active remote and returns its id.
func SeedRemote(tb testing.TB, s model.Store, url string) model.RemoteID {
	tb.Helper()
	id, err := s.CreateRemote(context.Background(), &model.Remote{
		URL:                 url,
		NormalizedURL:       url,
		Transport:           model.TransportHTTPS,
		TaintAnyTagDeletion: true,
		SyncInterval:        5 * time.Minute,
		StalenessBudget:     time.Hour,
		Status:              model.RemoteActive,
		ChainHeadHash:       make([]byte, 32),
		CreatedAtNS:         1_718_000_000_000_000_000,
		UpdatedAtNS:         1_718_000_000_000_000_000,
	})
	if err != nil {
		tb.Fatalf("SeedRemote: %v", err)
	}
	return id
}

// AssertChainIntact replays a remote's per-remote observation chain and
// asserts that recomputing row_hash = SHA256(prev_hash || canonical(row))
// from genesis (32 zero bytes) reproduces every stored row_hash, and that
// the final computed hash equals remotes.chain_head_hash with chain_len rows.
// Fails the test on any break.
func AssertChainIntact(tb testing.TB, ctx context.Context, s model.Store, remoteID model.RemoteID) {
	tb.Helper()
	head, length, err := s.GetChainHead(ctx, remoteID)
	if err != nil {
		tb.Fatalf("AssertChainIntact: GetChainHead remote=%d: %v", remoteID, err)
	}
	if length == 0 {
		// Genesis: chain_head must be 32 zero bytes.
		if len(head) != 32 {
			tb.Errorf("AssertChainIntact: genesis chain_head must be 32 bytes, got %d", len(head))
			return
		}
		for i, b := range head {
			if b != 0 {
				tb.Errorf("AssertChainIntact: genesis chain_head[%d] = %d, want 0", i, b)
				return
			}
		}
		return // vacuously intact
	}

	// Full chain replay: replay all observations from the beginning and recompute hashes.
	const batchSize = 500
	prevHash := make([]byte, 32) // genesis: 32 zero bytes
	var seq int64                // start from seq > 0
	var count int64

	for {
		batch, err := s.ReplayObservations(ctx, remoteID, model.Seq(seq), batchSize)
		if err != nil {
			tb.Fatalf("AssertChainIntact: ReplayObservations remote=%d seq>%d: %v", remoteID, seq, err)
		}
		if len(batch) == 0 {
			break
		}
		for i := range batch {
			obs := &batch[i]
			count++

			// Verify prev_hash matches the running chain head.
			if len(obs.PrevHash) != 32 {
				tb.Errorf("AssertChainIntact: obs seq=%d prev_hash len=%d want 32", obs.Seq, len(obs.PrevHash))
				return
			}
			for j := range prevHash {
				if prevHash[j] != obs.PrevHash[j] {
					tb.Errorf("AssertChainIntact: obs seq=%d prev_hash mismatch at byte %d: got %02x want %02x",
						obs.Seq, j, obs.PrevHash[j], prevHash[j])
					return
				}
			}

			// Recompute row_hash and verify.
			computed := replayRowHash(prevHash, obs)
			if len(obs.RowHash) != 32 {
				tb.Errorf("AssertChainIntact: obs seq=%d row_hash len=%d want 32", obs.Seq, len(obs.RowHash))
				return
			}
			if !bytes.Equal(computed, obs.RowHash) {
				tb.Errorf("AssertChainIntact: obs seq=%d row_hash mismatch: recomputed %x stored %x",
					obs.Seq, computed, obs.RowHash)
				return
			}
			prevHash = obs.RowHash
			seq = int64(obs.Seq)
		}
		if len(batch) < batchSize {
			break
		}
	}

	if count != length {
		tb.Errorf("AssertChainIntact: replayed %d obs but chain_len=%d", count, length)
		return
	}

	// Final hash must equal the stored chain_head_hash.
	if len(head) != 32 {
		tb.Errorf("AssertChainIntact: chain_head len=%d want 32", len(head))
		return
	}
	for j := range prevHash {
		if prevHash[j] != head[j] {
			tb.Errorf("AssertChainIntact: final hash mismatch: computed %x stored %x", prevHash, head)
			return
		}
	}
}

// replayRowHash recomputes row_hash = SHA256(prev_hash ‖ canonical(row)).
// This is a local copy of the store.CanonicalRow + store.RowHash logic so
// testutil does not import internal/store (avoiding potential import cycles
// if store ever imports testutil in future phases).
func replayRowHash(prevHash []byte, o *model.Observation) []byte {
	h := sha256.New()
	h.Write(prevHash)
	h.Write(replayCanonical(o))
	return h.Sum(nil)
}

func replayCanonical(o *model.Observation) []byte {
	buf := make([]byte, 0, 256)
	buf = replayWriteInt(buf, int64(o.RemoteID))
	buf = replayWriteInt(buf, int64(o.Seq))
	buf = replayWriteInt(buf, int64(o.RefID))
	buf = replayWriteField(buf, []byte(o.EventType))
	buf = replayWriteField(buf, o.PrevOID.Raw)
	buf = replayWriteField(buf, o.NewOID.Raw)
	buf = replayWriteField(buf, o.PrevPeeledOID.Raw)
	buf = replayWriteField(buf, o.NewPeeledOID.Raw)
	buf = replayWriteInt(buf, o.ObservedAtNS)
	buf = replayWriteField(buf, []byte(o.CanonicalMeta))
	return buf
}

func replayWriteField(buf, b []byte) []byte {
	var lp [8]byte
	binary.BigEndian.PutUint64(lp[:], uint64(len(b)))
	buf = append(buf, lp[:]...)
	return append(buf, b...)
}

func replayWriteInt(buf []byte, v int64) []byte {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], uint64(v)) //nolint:gosec // deliberate bit-pattern cast mirroring chain.go
	return replayWriteField(buf, x[:])
}
