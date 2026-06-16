//go:build mysql_it

// Package store MySQL integration suite. Build-tagged (mysql_it) so it is
// excluded from the default Docker-free gate. Run with:
//
//	make test-mysql        # or: go test -tags=mysql_it -count=1 ./internal/store/...
//
// It starts a throwaway mysql:8.4 container via testcontainers-go and exercises
// the SAME model.Store contract the SQLite impl is tested against
// (store_test.go + observation_chain_test.go), proving the second implementation
// is behavior-equivalent: remotes CRUD + soft-delete + dup-url conflict; refs
// upsert/list/get; observation append + per-remote SHA-256 chain integrity across
// multiple appends + a CAS-conflict path returning ErrChainCAS; LatestObservation
// ForRef; taint insert (sticky + idempotent-unique + ack); syncs; lease
// acquire/release with holder assertion + chain-head CAS; pagination.
package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tcmysql "github.com/testcontainers/testcontainers-go/modules/mysql"

	"github.com/mivanov93/git-tainted/internal/model"
)

// mysqlImage is the cached image tag — do NOT change to a non-cached tag
// (Docker Hub is rate-limited in this environment).
const mysqlImage = "mysql:8.4"

// newMySQLStore starts a mysql:8.4 container, opens an OpenMySQL store against it
// (which runs the MySQL migrations), and registers cleanup. The container is
// shared across the subtests of a single top-level test via t.Cleanup ordering.
func newMySQLStore(t *testing.T) (model.Store, *tcmysql.MySQLContainer) {
	t.Helper()
	ctx := context.Background()

	ctr, err := tcmysql.Run(ctx, mysqlImage,
		tcmysql.WithDatabase("git_tainted"),
		tcmysql.WithUsername("git"),
		tcmysql.WithPassword("gitpw"),
	)
	if err != nil {
		t.Fatalf("start mysql container: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = ctr.Terminate(ctx)
	})

	// The store REQUIRES these DSN params (asserted by validateMySQLDSN).
	dsn, err := ctr.ConnectionString(ctx,
		"multiStatements=true", "parseTime=false", "clientFoundRows=true")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	root := repoRoot(t)
	migrDir := filepath.Join(root, "db", "migrations-mysql")

	// OpenMySQL pings + migrates. The container log-wait can fire a touch before
	// the server accepts app connections, so retry the open briefly.
	var s model.Store
	deadline := time.Now().Add(60 * time.Second)
	for {
		s, err = OpenMySQL(dsn, migrDir)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("OpenMySQL did not become ready: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, ctr
}

// seedMySQLRemote inserts a minimal active remote (genesis chain head).
func seedMySQLRemote(t *testing.T, s model.Store, url string) model.RemoteID {
	t.Helper()
	id, err := s.CreateRemote(context.Background(), &model.Remote{
		URL:                 url,
		NormalizedURL:       url,
		Transport:           model.TransportHTTPS,
		TaintAnyTagDeletion: true,
		SyncIntervalNS:      300_000_000_000,
		StalenessBudgetNS:   3_600_000_000_000,
		Status:              model.RemoteActive,
		ChainHeadHash:       make([]byte, 32),
		CreatedAtNS:         1_718_000_000_000_000_000,
		UpdatedAtNS:         1_718_000_000_000_000_000,
	})
	if err != nil {
		t.Fatalf("seedMySQLRemote: %v", err)
	}
	return id
}

// TestMySQLStore_Contract drives the whole Store contract against one container.
func TestMySQLStore_Contract(t *testing.T) {
	s, ctr := newMySQLStore(t)
	ctx := context.Background()

	// Report the server version so the run proves it ran against mysql:8.4.
	if v, err := mysqlServerVersion(t, ctr); err == nil {
		t.Logf("connected MySQL server version: %s", v)
	}

	t.Run("RemoteCRUD_SoftDelete_DupConflict", func(t *testing.T) {
		r := &model.Remote{
			URL:                 "https://github.com/org/repo.git",
			NormalizedURL:       "https://github.com/org/repo.git",
			Transport:           model.TransportHTTPS,
			TaintAnyTagDeletion: true,
			SyncIntervalNS:      300_000_000_000,
			StalenessBudgetNS:   3_600_000_000_000,
			Status:              model.RemoteActive,
			ChainHeadHash:       make([]byte, 32),
			CreatedAtNS:         1_718_000_000_000_000_000,
			UpdatedAtNS:         1_718_000_000_000_000_000,
		}
		id, err := s.CreateRemote(ctx, r)
		if err != nil {
			t.Fatalf("CreateRemote: %v", err)
		}
		if id == 0 {
			t.Fatal("zero id")
		}

		got, err := s.GetRemote(ctx, id)
		if err != nil {
			t.Fatalf("GetRemote: %v", err)
		}
		if got.NormalizedURL != r.NormalizedURL {
			t.Errorf("NormalizedURL = %q, want %q", got.NormalizedURL, r.NormalizedURL)
		}
		if got.Transport != model.TransportHTTPS {
			t.Errorf("Transport = %q, want https", got.Transport)
		}
		if len(got.ChainHeadHash) != 32 {
			t.Errorf("ChainHeadHash len = %d, want 32", len(got.ChainHeadHash))
		}

		// GetRemoteByURL round-trip.
		byURL, err := s.GetRemoteByURL(ctx, r.NormalizedURL)
		if err != nil {
			t.Fatalf("GetRemoteByURL: %v", err)
		}
		if byURL.ID != id {
			t.Errorf("byURL.ID = %d, want %d", byURL.ID, id)
		}
		if _, err := s.GetRemoteByURL(ctx, "https://nope.example/x.git"); !errors.Is(err, model.ErrNotFound) {
			t.Errorf("missing url err = %v, want ErrNotFound", err)
		}

		// Dup normalized_url → ErrConflict.
		if _, err := s.CreateRemote(ctx, r); !errors.Is(err, model.ErrConflict) {
			t.Fatalf("dup url err = %v, want ErrConflict", err)
		}

		// UpdateRemote round-trip + not-found.
		got.LastErr = "boom"
		got.Status = model.RemoteDegraded
		got.UpdatedAtNS = 1_718_000_000_500_000_000
		if err := s.UpdateRemote(ctx, got); err != nil {
			t.Fatalf("UpdateRemote: %v", err)
		}
		reread, _ := s.GetRemote(ctx, id)
		if reread.Status != model.RemoteDegraded || reread.LastErr != "boom" {
			t.Errorf("update not persisted: status=%q lastErr=%q", reread.Status, reread.LastErr)
		}
		missing := &model.Remote{ID: 999999, ChainHeadHash: make([]byte, 32)}
		if err := s.UpdateRemote(ctx, missing); !errors.Is(err, model.ErrNotFound) {
			t.Errorf("UpdateRemote missing err = %v, want ErrNotFound", err)
		}

		// Soft-delete retains the row but stamps removed_at_ns.
		atNS := int64(1_718_000_001_000_000_000)
		if err := s.SoftDeleteRemote(ctx, id, atNS); err != nil {
			t.Fatalf("SoftDeleteRemote: %v", err)
		}
		del, err := s.GetRemote(ctx, id)
		if err != nil {
			t.Fatalf("GetRemote after soft-delete: %v", err)
		}
		if del.RemovedAtNS == nil || *del.RemovedAtNS != atNS {
			t.Errorf("RemovedAtNS = %v, want %d", del.RemovedAtNS, atNS)
		}
		// After soft-delete the URL lookup (which filters removed_at_ns IS NULL) misses.
		if _, err := s.GetRemoteByURL(ctx, r.NormalizedURL); !errors.Is(err, model.ErrNotFound) {
			t.Errorf("soft-deleted url lookup err = %v, want ErrNotFound", err)
		}
	})

	t.Run("RefsUpsertListGet", func(t *testing.T) {
		rid := seedMySQLRemote(t, s, "https://github.com/org/refs.git")
		ref := &model.Ref{
			RemoteID:    rid,
			TagName:     "v1.0.0",
			CurrentOID:  model.MustParseOID("1111111111111111111111111111111111111111", model.SHA1),
			FirstSeenNS: 1_718_000_000_000_000_000,
			LastSeenNS:  1_718_000_000_000_000_000,
		}
		if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
			return tx.UpsertRefProjection(ctx, ref)
		}); err != nil {
			t.Fatalf("UpsertRefProjection: %v", err)
		}
		if ref.ID == 0 {
			t.Fatal("upsert did not back-fill ref ID")
		}

		got, err := s.GetRef(ctx, rid, "v1.0.0")
		if err != nil {
			t.Fatalf("GetRef: %v", err)
		}
		if !got.CurrentOID.Equal(ref.CurrentOID) {
			t.Errorf("CurrentOID = %s, want %s", got.CurrentOID.Hex(), ref.CurrentOID.Hex())
		}
		if got.ID != ref.ID {
			t.Errorf("GetRef ID = %d, want %d", got.ID, ref.ID)
		}

		// Idempotent upsert: same unique key → same id, updated oid.
		ref2 := &model.Ref{
			RemoteID:   rid,
			TagName:    "v1.0.0",
			CurrentOID: model.MustParseOID("2222222222222222222222222222222222222222", model.SHA1),
			LastSeenNS: 1_718_000_000_100_000_000,
		}
		if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
			return tx.UpsertRefProjection(ctx, ref2)
		}); err != nil {
			t.Fatalf("second upsert: %v", err)
		}
		if ref2.ID != ref.ID {
			t.Errorf("upsert changed id: %d != %d", ref2.ID, ref.ID)
		}
		got2, _ := s.GetRef(ctx, rid, "v1.0.0")
		if !got2.CurrentOID.Equal(ref2.CurrentOID) {
			t.Errorf("upsert did not update oid: %s", got2.CurrentOID.Hex())
		}

		for _, name := range []string{"v1.1.0", "v2.0.0"} {
			r := &model.Ref{RemoteID: rid, TagName: name}
			if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
				return tx.UpsertRefProjection(ctx, r)
			}); err != nil {
				t.Fatalf("upsert %q: %v", name, err)
			}
		}
		tags, err := s.ListTags(ctx, rid)
		if err != nil {
			t.Fatalf("ListTags: %v", err)
		}
		if len(tags) != 3 {
			t.Errorf("ListTags len = %d, want 3", len(tags))
		}

		if _, err := s.GetRef(ctx, rid, "v9.9.9"); !errors.Is(err, model.ErrNotFound) {
			t.Errorf("missing tag err = %v, want ErrNotFound", err)
		}
	})

	t.Run("ObservationChain_AppendIntegrity_AndLatest", func(t *testing.T) {
		rid := seedMySQLRemote(t, s, "https://github.com/org/chain.git")
		ref := &model.Ref{
			RemoteID:   rid,
			TagName:    "v1.0.0",
			CurrentOID: model.MustParseOID("1111111111111111111111111111111111111111", model.SHA1),
		}

		oids := []string{
			"1111111111111111111111111111111111111111",
			"2222222222222222222222222222222222222222",
			"3333333333333333333333333333333333333333",
		}
		var lastSeq model.Seq
		for i, hexOID := range oids {
			err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
				if err := tx.UpsertRefProjection(ctx, ref); err != nil {
					return err
				}
				if _, err := tx.WriteSync(ctx, &model.Sync{
					RemoteID: rid, Trigger: model.TriggerManual,
					StartedNS: int64(i + 1), FinishedNS: int64(i + 1), Status: model.SyncOk,
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
				lastSeq = seq
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
			t.Fatalf("chain_len = %d, want 3", length)
		}
		if len(head) != 32 {
			t.Fatalf("chain head len = %d, want 32", len(head))
		}
		// Independent SHA-256 chain replay must reproduce head + length.
		assertMySQLChainIntact(t, ctx, s, rid)

		// LatestObservationForRef returns the highest-seq proof.
		proof, err := s.LatestObservationForRef(ctx, ref.ID)
		if err != nil {
			t.Fatalf("LatestObservationForRef: %v", err)
		}
		if proof.Seq != lastSeq {
			t.Errorf("proof.Seq = %d, want %d", proof.Seq, lastSeq)
		}
		if len(proof.RowHash) != 32 {
			t.Errorf("proof.RowHash len = %d, want 32", len(proof.RowHash))
		}
		if !bytes.Equal(proof.RowHash, head) {
			t.Errorf("latest row_hash must equal chain head")
		}

		// Empty ref → ErrNotFound.
		empty := &model.Ref{RemoteID: rid, TagName: "v-empty"}
		if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
			return tx.UpsertRefProjection(ctx, empty)
		}); err != nil {
			t.Fatalf("upsert empty ref: %v", err)
		}
		if _, err := s.LatestObservationForRef(ctx, empty.ID); !errors.Is(err, model.ErrNotFound) {
			t.Errorf("empty ref proof err = %v, want ErrNotFound", err)
		}
	})

	t.Run("ChainCAS_ConflictReturnsErrChainCAS", func(t *testing.T) {
		// The chain_head CAS is the correctness primitive that lets MySQL run a
		// NORMAL (non-serialized) connection pool: a writer captures the head as a
		// witness, and any advance whose witness no longer matches the live head
		// loses with model.ErrChainCAS. We drive that guard deterministically
		// through the lease witness path (Acquire captures the head; an
		// AppendObservation in between advances it; the stale-witness Release must
		// CAS-fail) — the same AdvanceRemoteChainHead WHERE-clause AppendObservation
		// itself relies on. No flaky goroutine race: InnoDB serializes two raw
		// concurrent AppendObservation calls via the remotes row lock, so the
		// witness path is the faithful, deterministic CAS-conflict trigger.
		rid := seedMySQLRemote(t, s, "https://github.com/org/cas.git")
		ref := &model.Ref{RemoteID: rid, TagName: "v1.0.0"}
		if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
			return tx.UpsertRefProjection(ctx, ref)
		}); err != nil {
			t.Fatalf("seed ref: %v", err)
		}

		appendOne := func(hexOID string, atNS int64) {
			t.Helper()
			if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
				if _, err := tx.WriteSync(ctx, &model.Sync{
					RemoteID: rid, Trigger: model.TriggerManual,
					StartedNS: atNS, FinishedNS: atNS, Status: model.SyncOk,
				}); err != nil {
					return err
				}
				o := &model.Observation{
					RemoteID:     rid,
					RefID:        ref.ID,
					EventType:    model.EventTagCreated,
					NewOID:       model.MustParseOID(hexOID, model.SHA1),
					ObservedAtNS: atNS,
				}
				_, err := tx.AppendObservation(ctx, o)
				return err
			}); err != nil {
				t.Fatalf("append %s: %v", hexOID, err)
			}
		}

		// First append → head advances to H1 at len=1.
		appendOne("1111111111111111111111111111111111111111", 1)

		// A writer captures the current head H1 as its lease witness.
		ok, witness, err := s.TryAcquireLease(ctx, rid, "stale-writer", 1, 1_000_000)
		if err != nil || !ok {
			t.Fatalf("acquire lease: ok=%v err=%v", ok, err)
		}

		// Meanwhile the chain advances out from under the witness (H1 → H2).
		// (Force-expire/steal the witness-holder's lease is unnecessary: the lease
		// only guards chain_head, and we exercise the CAS, not lease exclusion.)
		if err := s.ReleaseLeaseCAS(ctx, rid, "stale-writer", witness, witness, 1); err != nil {
			// Release with witness==newHead and same len is a no-op advance that just
			// frees the lease so the next append is unobstructed; tolerate ErrChainCAS
			// only if the head already moved (it has not here).
			t.Fatalf("release-to-free lease: %v", err)
		}
		appendOne("2222222222222222222222222222222222222222", 2) // head → H2 at len=2

		// Re-acquire and attempt a release with the STALE witness H1: the head is
		// now H2, so the CAS WHERE chain_head_hash=H1 matches nothing → ErrChainCAS.
		ok2, freshWitness, err := s.TryAcquireLease(ctx, rid, "stale-writer-2", 2, 1_000_000)
		if err != nil || !ok2 {
			t.Fatalf("re-acquire lease: ok=%v err=%v", ok2, err)
		}
		_ = freshWitness // we deliberately release with the stale H1, not this fresh one.
		newHead := make([]byte, 32)
		newHead[0] = 0xEE
		relErr := s.ReleaseLeaseCAS(ctx, rid, "stale-writer-2", witness /* stale H1 */, newHead, 3)
		if !errors.Is(relErr, model.ErrChainCAS) {
			t.Fatalf("stale-witness release err = %v, want ErrChainCAS", relErr)
		}

		// The failed CAS left the chain untouched and intact.
		assertMySQLChainIntact(t, ctx, s, rid)
	})

	t.Run("TaintEvents_StickyIdempotentAck", func(t *testing.T) {
		rid := seedMySQLRemote(t, s, "https://github.com/org/taint.git")
		ref := &model.Ref{RemoteID: rid, TagName: "v1.0.0"}
		if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
			return tx.UpsertRefProjection(ctx, ref)
		}); err != nil {
			t.Fatalf("seed ref: %v", err)
		}

		from := model.MustParseOID("1111111111111111111111111111111111111111", model.SHA1)
		to := model.MustParseOID("2222222222222222222222222222222222222222", model.SHA1)
		te := &model.TaintEvent{
			RemoteID:     rid,
			RefID:        ref.ID,
			Reason:       model.TaintTagOIDChanged,
			FromOID:      from,
			ToOID:        to,
			DetectedAtNS: 1_718_000_000_000_000_001,
			Detail:       "moved",
		}
		var evID int64
		if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
			var err error
			evID, err = tx.AppendTaintEvent(ctx, te)
			return err
		}); err != nil {
			t.Fatalf("AppendTaintEvent: %v", err)
		}
		if evID == 0 {
			t.Fatal("taint event id must be non-zero")
		}

		// Idempotent: re-insert the SAME (remote,ref,reason,from,to) → same id.
		te2 := &model.TaintEvent{
			RemoteID: rid, RefID: ref.ID, Reason: model.TaintTagOIDChanged,
			FromOID: from, ToOID: to, DetectedAtNS: 9_999_999_999_999, Detail: "dup",
		}
		dupID, err := s.AppendTaintEvent(ctx, te2)
		if err != nil {
			t.Fatalf("idempotent AppendTaintEvent: %v", err)
		}
		if dupID != evID {
			t.Errorf("idempotent insert id = %d, want original %d", dupID, evID)
		}

		events, _, err := s.ListTaintEvents(ctx, rid, 10, 0)
		if err != nil {
			t.Fatalf("ListTaintEvents: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("events len = %d, want 1 (idempotent)", len(events))
		}
		if events[0].DetectedAtNS != te.DetectedAtNS {
			t.Errorf("detected_at_ns = %d, want original %d (idempotent keeps first)", events[0].DetectedAtNS, te.DetectedAtNS)
		}

		// Ack annotates the event.
		if err := s.AckTaintEvent(ctx, evID, "operator", "reviewed", 1_718_000_000_000_000_002); err != nil {
			t.Fatalf("AckTaintEvent: %v", err)
		}
		acked, _, _ := s.ListTaintEvents(ctx, rid, 10, 0)
		if acked[0].AckedAtNS == nil || acked[0].AckedBy != "operator" {
			t.Errorf("ack not persisted: %+v", acked[0])
		}

		// SetRefTaint stickiness on the ref projection.
		if err := s.SetRefTaint(ctx, ref.ID, 1_718_000_000_000_000_003); err != nil {
			t.Fatalf("SetRefTaint: %v", err)
		}
		tref, _ := s.GetRef(ctx, rid, "v1.0.0")
		if !tref.Tainted || tref.TaintFirstNS == nil {
			t.Errorf("ref not marked tainted: %+v", tref)
		}
	})

	t.Run("Syncs", func(t *testing.T) {
		rid := seedMySQLRemote(t, s, "https://github.com/org/syncs.git")
		sy := &model.Sync{
			RemoteID: rid, Trigger: model.TriggerManual,
			StartedNS: 1_718_000_000_000_000_000, FinishedNS: 1_718_000_000_001_000_000,
			Status: model.SyncOk, TagsSeen: 5, TagsChanged: 1,
		}
		if err := s.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
			_, err := tx.WriteSync(ctx, sy)
			return err
		}); err != nil {
			t.Fatalf("WriteSync: %v", err)
		}
		syncs, _, err := s.ListSyncs(ctx, rid, 10, 0)
		if err != nil {
			t.Fatalf("ListSyncs: %v", err)
		}
		if len(syncs) != 1 || syncs[0].TagsSeen != 5 {
			t.Fatalf("ListSyncs = %+v, want 1 row TagsSeen=5", syncs)
		}
	})

	t.Run("Lease_AcquireReleaseHolderCAS", func(t *testing.T) {
		rid := seedMySQLRemote(t, s, "https://github.com/org/lease.git")

		// Acquire returns the genesis witness.
		ok, witness, err := s.TryAcquireLease(ctx, rid, "inst-A", 1_000, 11_000)
		if err != nil {
			t.Fatalf("TryAcquireLease A: %v", err)
		}
		if !ok {
			t.Fatal("A failed to acquire a free lease")
		}
		if len(witness) != 32 {
			t.Fatalf("witness len = %d, want 32", len(witness))
		}

		// A second live holder is rejected.
		ok2, _, err := s.TryAcquireLease(ctx, rid, "inst-B", 2_000, 12_000)
		if err != nil {
			t.Fatalf("TryAcquireLease B: %v", err)
		}
		if ok2 {
			t.Fatal("B acquired a lease already held by A")
		}

		// Release MUST assert holder ownership: a non-holder release fails.
		newHead := make([]byte, 32)
		newHead[0] = 0xAB
		if err := s.ReleaseLeaseCAS(ctx, rid, "inst-B", witness, newHead, 1); !errors.Is(err, model.ErrLeaseLost) {
			t.Fatalf("non-holder release err = %v, want ErrLeaseLost", err)
		}

		// The rightful holder releases, advancing the chain via CAS (witness=genesis).
		if err := s.ReleaseLeaseCAS(ctx, rid, "inst-A", witness, newHead, 1); err != nil {
			t.Fatalf("holder release: %v", err)
		}
		head, length, _ := s.GetChainHead(ctx, rid)
		if length != 1 || !bytes.Equal(head, newHead) {
			t.Errorf("chain not advanced by release: len=%d head=%x", length, head)
		}

		// A stale-witness release after the head moved must fail the CAS.
		ok3, w3, err := s.TryAcquireLease(ctx, rid, "inst-C", 3_000, 13_000)
		if err != nil || !ok3 {
			t.Fatalf("re-acquire after release: ok=%v err=%v", ok3, err)
		}
		staleWitness := make([]byte, 32) // genesis, but head is now newHead
		other := make([]byte, 32)
		other[0] = 0xCD
		if err := s.ReleaseLeaseCAS(ctx, rid, "inst-C", staleWitness, other, 2); !errors.Is(err, model.ErrChainCAS) {
			t.Fatalf("stale-witness release err = %v, want ErrChainCAS", err)
		}
		_ = w3
	})

	t.Run("ListRemotes_Pagination", func(t *testing.T) {
		// Fresh URLs so this is independent of earlier subtests.
		for i := 0; i < 4; i++ {
			seedMySQLRemote(t, s, fmt.Sprintf("https://github.com/org/page-%d.git", i))
		}
		page1, next1, err := s.ListRemotes(ctx, 2, 0)
		if err != nil {
			t.Fatalf("page1: %v", err)
		}
		if len(page1) != 2 {
			t.Fatalf("page1 len = %d, want 2", len(page1))
		}
		page2, _, err := s.ListRemotes(ctx, 2, next1)
		if err != nil {
			t.Fatalf("page2: %v", err)
		}
		if len(page2) != 2 {
			t.Fatalf("page2 len = %d, want 2", len(page2))
		}
		// Cursor strictly advances.
		if page2[0].ID <= page1[len(page1)-1].ID {
			t.Errorf("pagination cursor did not advance: %d <= %d", page2[0].ID, page1[len(page1)-1].ID)
		}
	})
}

// mysqlServerVersion reads SELECT VERSION() via a throwaway exec in the container,
// proving the suite ran against a real mysql:8.x server (not the Docker daemon
// version testcontainers logs). Uses the app credentials configured in
// newMySQLStore (git/gitpw); the root account is password-protected.
func mysqlServerVersion(t *testing.T, ctr *tcmysql.MySQLContainer) (string, error) {
	t.Helper()
	ctx := context.Background()
	code, reader, err := ctr.Exec(ctx, []string{
		"mysql", "-N", "-B", "-ugit", "-pgitpw", "git_tainted", "-e", "SELECT VERSION()",
	})
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(reader)
	raw := buf.String()
	if code != 0 {
		return "", fmt.Errorf("mysql VERSION() exit code %d: %s", code, strings.TrimSpace(raw))
	}
	// The exec stream multiplexes stdout+stderr (incl. the "Using a password ..."
	// warning) and is framed with control bytes; pick the token that looks like a
	// semantic version (e.g. "8.4.9").
	for _, f := range strings.Fields(raw) {
		t := strings.Map(func(r rune) rune {
			if (r >= '0' && r <= '9') || r == '.' || r == '-' {
				return r
			}
			return -1
		}, f)
		if strings.Count(t, ".") >= 2 {
			return t, nil
		}
	}
	return strings.TrimSpace(raw), nil
}

// assertMySQLChainIntact replays a remote's observation chain and recomputes
// row_hash = SHA256(prev_hash ‖ canonical(row)) from genesis, asserting it
// reproduces every stored row_hash and the final chain head + length. This is a
// local copy of the testutil assertion so the build-tagged IT does not pull the
// testutil package (which is SQLite-bound).
func assertMySQLChainIntact(t *testing.T, ctx context.Context, s model.Store, remoteID model.RemoteID) {
	t.Helper()
	head, length, err := s.GetChainHead(ctx, remoteID)
	if err != nil {
		t.Fatalf("assertMySQLChainIntact: GetChainHead: %v", err)
	}
	prevHash := make([]byte, 32)
	var seq int64
	var count int64
	for {
		batch, err := s.ReplayObservations(ctx, remoteID, model.Seq(seq), 500)
		if err != nil {
			t.Fatalf("assertMySQLChainIntact: ReplayObservations: %v", err)
		}
		if len(batch) == 0 {
			break
		}
		for i := range batch {
			obs := &batch[i]
			count++
			if !bytes.Equal(obs.PrevHash, prevHash) {
				t.Fatalf("chain break at seq=%d: prev_hash %x != running %x", obs.Seq, obs.PrevHash, prevHash)
			}
			computed := mysqlReplayRowHash(prevHash, obs)
			if !bytes.Equal(computed, obs.RowHash) {
				t.Fatalf("row_hash mismatch at seq=%d: recomputed %x stored %x", obs.Seq, computed, obs.RowHash)
			}
			prevHash = obs.RowHash
			seq = int64(obs.Seq)
		}
		if len(batch) < 500 {
			break
		}
	}
	if count != length {
		t.Fatalf("replayed %d obs but chain_len=%d", count, length)
	}
	if !bytes.Equal(prevHash, head) {
		t.Fatalf("final hash %x != stored chain head %x", prevHash, head)
	}
}

func mysqlReplayRowHash(prevHash []byte, o *model.Observation) []byte {
	h := sha256.New()
	h.Write(prevHash)
	h.Write(mysqlReplayCanonical(o))
	return h.Sum(nil)
}

func mysqlReplayCanonical(o *model.Observation) []byte {
	buf := make([]byte, 0, 256)
	buf = mysqlReplayWriteInt(buf, int64(o.RemoteID))
	buf = mysqlReplayWriteInt(buf, int64(o.Seq))
	buf = mysqlReplayWriteInt(buf, int64(o.RefID))
	buf = mysqlReplayWriteField(buf, []byte(o.EventType))
	buf = mysqlReplayWriteField(buf, o.PrevOID.Raw)
	buf = mysqlReplayWriteField(buf, o.NewOID.Raw)
	buf = mysqlReplayWriteField(buf, o.PrevPeeledOID.Raw)
	buf = mysqlReplayWriteField(buf, o.NewPeeledOID.Raw)
	buf = mysqlReplayWriteInt(buf, o.ObservedAtNS)
	buf = mysqlReplayWriteField(buf, []byte(o.CanonicalMeta))
	return buf
}

func mysqlReplayWriteField(buf, b []byte) []byte {
	var lp [8]byte
	binary.BigEndian.PutUint64(lp[:], uint64(len(b)))
	buf = append(buf, lp[:]...)
	return append(buf, b...)
}

func mysqlReplayWriteInt(buf []byte, v int64) []byte {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], uint64(v)) //nolint:gosec // deliberate bit-pattern cast mirroring chain.go
	return mysqlReplayWriteField(buf, x[:])
}
