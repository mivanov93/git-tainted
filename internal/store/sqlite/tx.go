package sqlite

import (
	"context"
	"fmt"

	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/store"
	"github.com/mivanov93/git-tainted/internal/store/sqlite/sqlc"
)

// sqliteTx implements model.Tx inside a single SQLite write transaction.
type sqliteTx struct {
	q      *sqlc.Queries // bound to the transaction
	syncID model.SyncID  // set by WriteSync; used by AppendObservation FK
}

// WithTx opens a write transaction and calls fn with a sqliteTx. If fn
// returns nil the transaction is committed; otherwise it is rolled back.
func (s *sqliteStore) WithTx(ctx context.Context, fn func(ctx context.Context, tx model.Tx) error) error {
	dbTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("WithTx begin: %w", err)
	}
	stx := &sqliteTx{q: sqlc.New(dbTx)}
	if fnErr := fn(ctx, stx); fnErr != nil {
		_ = dbTx.Rollback()
		return fnErr
	}
	if err := dbTx.Commit(); err != nil {
		return fmt.Errorf("WithTx commit: %w", err)
	}
	return nil
}

// AppendObservation appends one observation to the remote's per-remote chain,
// advancing chain_head_hash/chain_len in the SAME txn.
// It reads the current head, assigns seq = chain_len+1, sets prev_hash = head,
// computes row_hash = SHA256(prev_hash ‖ canonical(row)), inserts, and CAS-
// advances the remote. A failed CAS returns ErrChainCAS.
func (t *sqliteTx) AppendObservation(ctx context.Context, o *model.Observation) (model.Seq, error) {
	if t.syncID == 0 && o.SyncID == 0 {
		return 0, fmt.Errorf("store: AppendObservation called without a prior WriteSync (sync_id is 0)")
	}
	effectiveSyncID := t.syncID
	if o.SyncID != 0 {
		effectiveSyncID = o.SyncID
	}

	headRow, err := t.q.GetRemoteChainHead(ctx, int64(o.RemoteID))
	if err != nil {
		return 0, fmt.Errorf("get chain head: %w", err)
	}
	prevHash := headRow.ChainHeadHash
	if len(prevHash) != store.ChainHashLen {
		return 0, fmt.Errorf("remote %d chain_head malformed (len %d)", o.RemoteID, len(prevHash))
	}
	seq := model.Seq(headRow.ChainLen + 1)

	o.Seq = seq
	o.PrevHash = prevHash
	o.RowHash = store.RowHash(prevHash, o)

	var canonicalMeta interface{}
	if o.CanonicalMeta != "" {
		canonicalMeta = o.CanonicalMeta
	}

	id, err := t.q.InsertObservation(ctx, sqlc.InsertObservationParams{
		RemoteID:      int64(o.RemoteID),
		RefID:         int64(o.RefID),
		SyncID:        int64(effectiveSyncID),
		Seq:           int64(seq),
		EventType:     string(o.EventType),
		PrevOid:       nullBytes(o.PrevOID.Raw),
		NewOid:        nullBytes(o.NewOID.Raw),
		PrevPeeledOid: nullBytes(o.PrevPeeledOID.Raw),
		NewPeeledOid:  nullBytes(o.NewPeeledOID.Raw),
		ObservedAtNs:  o.ObservedAtNS,
		PrevHash:      o.PrevHash,
		RowHash:       o.RowHash,
		CanonicalMeta: canonicalMeta,
	})
	if err != nil {
		return 0, fmt.Errorf("insert observation: %w", err)
	}
	o.ID = id

	newLen := headRow.ChainLen + 1
	rows, err := t.q.AdvanceRemoteChainHead(ctx, sqlc.AdvanceRemoteChainHeadParams{
		ChainHeadHash:   o.RowHash,
		ChainLen:        newLen,
		ID:              int64(o.RemoteID),
		ChainHeadHash_2: prevHash,
		ChainLen_2:      headRow.ChainLen,
	})
	if err != nil {
		return 0, fmt.Errorf("advance chain head: %w", err)
	}
	if rows != 1 {
		return 0, fmt.Errorf("advance chain head: %w", model.ErrChainCAS)
	}
	return seq, nil
}

// UpsertRefProjection upserts a tag's current-state projection row.
func (t *sqliteTx) UpsertRefProjection(ctx context.Context, ref *model.Ref) error {
	var taintFirstNs interface{}
	if ref.TaintFirstNS != nil {
		taintFirstNs = *ref.TaintFirstNS
	}
	row, err := t.q.UpsertRef(ctx, sqlc.UpsertRefParams{
		RemoteID:         int64(ref.RemoteID),
		TagName:          ref.TagName,
		CurrentOid:       nullBytes(ref.CurrentOID.Raw),
		CurrentPeeledOid: nullBytes(ref.CurrentPeeledOID.Raw),
		IsAnnotated:      boolToInt(ref.IsAnnotatedTag),
		FirstOid:         nullBytes(ref.FirstOID.Raw),
		FirstSeenNs:      ref.FirstSeenNS,
		LastSeenNs:       ref.LastSeenNS,
		LastChangedNs:    ref.LastChangedNS,
		Deleted:          boolToInt(ref.Deleted),
		Tainted:          boolToInt(ref.Tainted),
		TaintFirstNs:     taintFirstNs,
		ObservationCount: ref.ObservationCount,
	})
	if err != nil {
		return fmt.Errorf("upsert ref %q: %w", ref.TagName, err)
	}
	ref.ID = model.RefID(row.ID)
	ref.RemoteID = model.RemoteID(row.RemoteID)
	return nil
}

// WriteSync inserts a syncs audit row and records the SyncID on the Tx so
// subsequent AppendObservation calls can reference it via the deferred FK.
func (t *sqliteTx) WriteSync(ctx context.Context, s *model.Sync) (model.SyncID, error) {
	id, err := t.q.InsertSync(ctx, sqlc.InsertSyncParams{
		RemoteID:        int64(s.RemoteID),
		Trigger:         string(s.Trigger),
		StartedNs:       s.StartedNS,
		FinishedNs:      s.FinishedNS,
		Status:          string(s.Status),
		TagsSeen:        int64(s.TagsSeen),
		TagsChanged:     int64(s.TagsChanged),
		Error:           s.Error,
		ChainHeadBefore: nullBytes(s.ChainHeadBefore),
		ChainHeadAfter:  nullBytes(s.ChainHeadAfter),
	})
	if err != nil {
		return 0, fmt.Errorf("insert sync: %w", err)
	}
	t.syncID = model.SyncID(id)
	s.ID = t.syncID
	return t.syncID, nil
}

// AdvanceChainHead performs a non-CAS chain head advance (used by Lock.Release).
func (t *sqliteTx) AdvanceChainHead(ctx context.Context, remoteID model.RemoteID, newHead []byte, newLen int64) error {
	return t.q.AdvanceChainHead(ctx, sqlc.AdvanceChainHeadParams{
		ChainHeadHash: newHead,
		ChainLen:      newLen,
		ID:            int64(remoteID),
	})
}

// CreateRemote inserts a remotes row inside the txn and returns its id. Mirrors
// sqliteStore.CreateRemote exactly, but bound to the transaction's *sqlc.Queries
// so the seed bootstrap creates remotes and rebuilds their chains atomically in
// one WithTx (spec §4.5 step 1).
func (t *sqliteTx) CreateRemote(ctx context.Context, r *model.Remote) (model.RemoteID, error) {
	row, err := t.q.CreateRemote(ctx, sqlc.CreateRemoteParams{
		Url:                 r.URL,
		NormalizedUrl:       r.NormalizedURL,
		Transport:           string(r.Transport),
		SyncIntervalNs:      int64(r.SyncInterval),
		StalenessBudgetNs:   int64(r.StalenessBudget),
		TaintAnyTagDeletion: boolToInt(r.TaintAnyTagDeletion),
		HashAlgo:            nullStringInterface(hashAlgoPtr(r.HashAlgo)),
		Status:              string(r.Status),
		LastOkNs:            r.LastOkNS,
		LastErr:             r.LastErr,
		ConsecutiveFailures: int64(r.ConsecutiveFailures),
		ChainHeadHash:       r.ChainHeadHash,
		ChainLen:            r.ChainLen,
		RemovedAtNs:         nullInt64Interface(r.RemovedAtNS),
		CreatedAtNs:         r.CreatedAtNS,
		UpdatedAtNs:         r.UpdatedAtNS,
	})
	if err != nil {
		if isUniqueConflict(err) {
			return 0, fmt.Errorf("CreateRemote normalized_url=%q: %w", r.NormalizedURL, model.ErrConflict)
		}
		return 0, fmt.Errorf("CreateRemote: %w", err)
	}
	return model.RemoteID(row.ID), nil
}

// CountAllRemotes counts all remotes rows (incl. soft-deleted) on the txn's
// connection — the seed in-txn zero-rows guard (spec §4.5 step 0 / M2).
func (t *sqliteTx) CountAllRemotes(ctx context.Context) (int64, error) {
	n, err := t.q.CountAllRemotes(ctx)
	if err != nil {
		return 0, fmt.Errorf("CountAllRemotes: %w", err)
	}
	return n, nil
}

// AppendTaintEvent inserts an immutable taint_events row inside the txn.
func (t *sqliteTx) AppendTaintEvent(ctx context.Context, e *model.TaintEvent) (int64, error) {
	var observationID interface{}
	if e.ObservationID != nil {
		observationID = *e.ObservationID
	}
	id, err := t.q.InsertTaintEvent(ctx, sqlc.InsertTaintEventParams{
		RemoteID:      int64(e.RemoteID),
		RefID:         int64(e.RefID),
		Reason:        string(e.Reason),
		ObservationID: observationID,
		FromOid:       nullBytes(e.FromOID.Raw),
		ToOid:         nullBytes(e.ToOID.Raw),
		DetectedAtNs:  e.DetectedAtNS,
		Detail:        e.Detail,
	})
	if err != nil {
		return 0, fmt.Errorf("insert taint_event: %w", err)
	}
	return id, nil
}

// ---- Helpers ---------------------------------------------------------------

// nullBytes converts a byte slice to interface{}: nil if empty, otherwise the bytes.
func nullBytes(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}

// Verify sqliteTx satisfies model.Tx at compile time.
var _ model.Tx = (*sqliteTx)(nil)
