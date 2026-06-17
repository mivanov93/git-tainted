package mysql

import (
	"context"
	"fmt"

	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/store"
	"github.com/mivanov93/git-tainted/internal/store/mysql/mysqlc"
)

// mysqlTx implements model.Tx inside a single MySQL write transaction. It
// mirrors sqliteTx exactly; the dialect differences (LastInsertId instead of
// RETURNING, id read-back for upsert/idempotent rows) are confined to the
// queries it calls.
type mysqlTx struct {
	q      *mysqlc.Queries // bound to the transaction
	syncID model.SyncID    // set by WriteSync; used by AppendObservation FK
}

// WithTx opens a write transaction and calls fn with a mysqlTx. If fn returns
// nil the transaction is committed; otherwise it is rolled back.
func (s *mysqlStore) WithTx(ctx context.Context, fn func(ctx context.Context, tx model.Tx) error) error {
	dbTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("WithTx begin: %w", err)
	}
	mtx := &mysqlTx{q: mysqlc.New(dbTx)}
	if fnErr := fn(ctx, mtx); fnErr != nil {
		_ = dbTx.Rollback()
		return fnErr
	}
	if err := dbTx.Commit(); err != nil {
		return fmt.Errorf("WithTx commit: %w", err)
	}
	return nil
}

// AppendObservation appends one observation to the remote's per-remote chain,
// advancing chain_head_hash/chain_len in the SAME txn. Identical algorithm to
// sqliteTx.AppendObservation: read head → seq=len+1 → prev_hash=head →
// row_hash = SHA256(prev_hash ‖ canonical(row)) via chain.go → insert
// (LastInsertId) → CAS-advance. A failed CAS returns ErrChainCAS.
func (t *mysqlTx) AppendObservation(ctx context.Context, o *model.Observation) (model.Seq, error) {
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
	o.RowHash = store.RowHash(prevHash, o) // parent store — dialect-agnostic

	id, err := t.q.InsertObservation(ctx, mysqlc.InsertObservationParams{
		RemoteID:      int64(o.RemoteID),
		RefID:         int64(o.RefID),
		SyncID:        int64(effectiveSyncID),
		Seq:           int64(seq),
		EventType:     string(o.EventType),
		PrevOid:       nullStringFromBytes(o.PrevOID.Raw),
		NewOid:        nullStringFromBytes(o.NewOID.Raw),
		PrevPeeledOid: nullStringFromBytes(o.PrevPeeledOID.Raw),
		NewPeeledOid:  nullStringFromBytes(o.NewPeeledOID.Raw),
		ObservedAtNs:  o.ObservedAtNS,
		PrevHash:      o.PrevHash,
		RowHash:       o.RowHash,
		CanonicalMeta: nullStringFromStr(o.CanonicalMeta),
	})
	if err != nil {
		return 0, fmt.Errorf("insert observation: %w", err)
	}
	o.ID = id

	newLen := headRow.ChainLen + 1
	rows, err := t.q.AdvanceRemoteChainHead(ctx, mysqlc.AdvanceRemoteChainHeadParams{
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

// UpsertRefProjection upserts a tag's current-state projection row, then reads
// the id+remote_id back (MySQL has no RETURNING).
func (t *mysqlTx) UpsertRefProjection(ctx context.Context, ref *model.Ref) error {
	if err := t.q.UpsertRef(ctx, mysqlc.UpsertRefParams{
		RemoteID:         int64(ref.RemoteID),
		TagName:          ref.TagName,
		CurrentOid:       nullStringFromBytes(ref.CurrentOID.Raw),
		CurrentPeeledOid: nullStringFromBytes(ref.CurrentPeeledOID.Raw),
		IsAnnotated:      boolToInt32(ref.IsAnnotatedTag),
		FirstOid:         nullStringFromBytes(ref.FirstOID.Raw),
		FirstSeenNs:      ref.FirstSeenNS,
		LastSeenNs:       ref.LastSeenNS,
		LastChangedNs:    ref.LastChangedNS,
		Deleted:          boolToInt32(ref.Deleted),
		Tainted:          boolToInt32(ref.Tainted),
		TaintFirstNs:     nullInt64FromPtr(ref.TaintFirstNS),
		ObservationCount: ref.ObservationCount,
	}); err != nil {
		return fmt.Errorf("upsert ref %q: %w", ref.TagName, err)
	}
	idRow, err := t.q.GetRefIDByName(ctx, mysqlc.GetRefIDByNameParams{
		RemoteID: int64(ref.RemoteID),
		TagName:  ref.TagName,
	})
	if err != nil {
		return fmt.Errorf("upsert ref %q read-back: %w", ref.TagName, err)
	}
	ref.ID = model.RefID(idRow.ID)
	ref.RemoteID = model.RemoteID(idRow.RemoteID)
	return nil
}

// WriteSync inserts a syncs audit row and records the SyncID on the Tx so
// subsequent AppendObservation calls can reference it.
func (t *mysqlTx) WriteSync(ctx context.Context, s *model.Sync) (model.SyncID, error) {
	id, err := t.q.InsertSync(ctx, mysqlc.InsertSyncParams{
		RemoteID:        int64(s.RemoteID),
		Trigger:         string(s.Trigger),
		StartedNs:       s.StartedNS,
		FinishedNs:      s.FinishedNS,
		Status:          string(s.Status),
		TagsSeen:        int32(s.TagsSeen),    //nolint:gosec // tag count, fits int32
		TagsChanged:     int32(s.TagsChanged), //nolint:gosec // tag count, fits int32
		Error:           s.Error,
		ChainHeadBefore: nullStringFromBytes(s.ChainHeadBefore),
		ChainHeadAfter:  nullStringFromBytes(s.ChainHeadAfter),
	})
	if err != nil {
		return 0, fmt.Errorf("insert sync: %w", err)
	}
	t.syncID = model.SyncID(id)
	s.ID = t.syncID
	return t.syncID, nil
}

// PruneSyncs enforces sync-audit retention (see model.Tx).
func (t *mysqlTx) PruneSyncs(ctx context.Context, remoteID model.RemoteID, keep int) error {
	return t.q.PruneSyncs(ctx, mysqlc.PruneSyncsParams{
		RemoteID:   int64(remoteID),
		RemoteID_2: int64(remoteID),
		Limit:      int32(keep), //nolint:gosec // retention count, fits int32
		RemoteID_3: int64(remoteID),
	})
}

// AdvanceChainHead performs a non-CAS chain head advance (used by Lock.Release).
func (t *mysqlTx) AdvanceChainHead(ctx context.Context, remoteID model.RemoteID, newHead []byte, newLen int64) error {
	return t.q.AdvanceChainHead(ctx, mysqlc.AdvanceChainHeadParams{
		ChainHeadHash: newHead,
		ChainLen:      newLen,
		ID:            int64(remoteID),
	})
}

// CreateRemote inserts a remotes row inside the txn and returns its id (via
// LastInsertId). Mirrors mysqlStore.CreateRemote, but bound to the transaction's
// *mysqlc.Queries so the seed bootstrap creates remotes and rebuilds their chains
// atomically in one WithTx (spec §4.5 step 1).
func (t *mysqlTx) CreateRemote(ctx context.Context, r *model.Remote) (model.RemoteID, error) {
	id, err := t.q.CreateRemote(ctx, mysqlc.CreateRemoteParams{
		Url:                 r.URL,
		NormalizedUrl:       r.NormalizedURL,
		Transport:           string(r.Transport),
		SyncIntervalNs:      int64(r.SyncInterval),
		StalenessBudgetNs:   int64(r.StalenessBudget),
		TaintAnyTagDeletion: boolToInt32(r.TaintAnyTagDeletion),
		HashAlgo:            nullStringFromStrPtr(hashAlgoPtr(r.HashAlgo)),
		Status:              string(r.Status),
		LastOkNs:            r.LastOkNS,
		LastErr:             r.LastErr,
		ConsecutiveFailures: int32(r.ConsecutiveFailures), //nolint:gosec // count, fits int32
		ChainHeadHash:       r.ChainHeadHash,
		ChainLen:            r.ChainLen,
		RemovedAtNs:         nullInt64FromPtr(r.RemovedAtNS),
		CreatedAtNs:         r.CreatedAtNS,
		UpdatedAtNs:         r.UpdatedAtNS,
	})
	if err != nil {
		if isMySQLUniqueConflict(err) {
			return 0, fmt.Errorf("CreateRemote normalized_url=%q: %w", r.NormalizedURL, model.ErrConflict)
		}
		return 0, fmt.Errorf("CreateRemote: %w", err)
	}
	return model.RemoteID(id), nil
}

// CountAllRemotes counts all remotes rows (incl. soft-deleted) on the txn's
// connection — the seed in-txn zero-rows guard (spec §4.5 step 0 / M2).
func (t *mysqlTx) CountAllRemotes(ctx context.Context) (int64, error) {
	n, err := t.q.CountAllRemotes(ctx)
	if err != nil {
		return 0, fmt.Errorf("CountAllRemotes: %w", err)
	}
	return n, nil
}

// AppendTaintEvent inserts an immutable taint_events row inside the txn,
// idempotent on the unique key.
func (t *mysqlTx) AppendTaintEvent(ctx context.Context, e *model.TaintEvent) (int64, error) {
	return insertTaintEventMySQL(ctx, t.q, e)
}

// insertTaintEventMySQL inserts (idempotently) a taint event and returns its id.
// Shared by mysqlStore.AppendTaintEvent and mysqlTx.AppendTaintEvent. Because the
// insert is INSERT ... ON DUPLICATE KEY UPDATE, LastInsertId is 0 on the
// duplicate path; in that case the id is read back via the unique key with the
// null-safe (<=>) comparison so a pre-existing event returns its original id
// (idempotent — same behavior as the SQLite RETURNING-on-conflict path).
func insertTaintEventMySQL(ctx context.Context, q *mysqlc.Queries, e *model.TaintEvent) (int64, error) {
	id, err := q.InsertTaintEvent(ctx, mysqlc.InsertTaintEventParams{
		RemoteID:      int64(e.RemoteID),
		RefID:         int64(e.RefID),
		Reason:        string(e.Reason),
		ObservationID: nullInt64FromPtr(e.ObservationID),
		FromOid:       nullStringFromBytes(e.FromOID.Raw),
		ToOid:         nullStringFromBytes(e.ToOID.Raw),
		DetectedAtNs:  e.DetectedAtNS,
		Detail:        e.Detail,
	})
	if err != nil {
		return 0, fmt.Errorf("insert taint_event: %w", err)
	}
	if id != 0 {
		return id, nil
	}
	// Duplicate path (id==0): read back the original row's id.
	got, err := q.GetTaintEventID(ctx, mysqlc.GetTaintEventIDParams{
		RemoteID: int64(e.RemoteID),
		RefID:    int64(e.RefID),
		Reason:   string(e.Reason),
		FromOid:  nullStringFromBytes(e.FromOID.Raw),
		ToOid:    nullStringFromBytes(e.ToOID.Raw),
	})
	if err != nil {
		return 0, fmt.Errorf("insert taint_event read-back: %w", err)
	}
	return got, nil
}

// Verify mysqlTx satisfies model.Tx at compile time.
var _ model.Tx = (*mysqlTx)(nil)
