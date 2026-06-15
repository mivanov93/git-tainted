// Package store implements model.Store over sqlc-generated queries against
// modernc.org/sqlite (pure-Go, CGO-free).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/store/sqlc"
)

// nowNS returns the current wall time as unix-nanoseconds.
func nowNS() int64 { return time.Now().UnixNano() }

// sqliteStore implements model.Store over sqlc queries + modernc.org/sqlite.
type sqliteStore struct {
	db      *sql.DB
	q       *sqlc.Queries
	migrDir string
}

// Open opens (or creates) a SQLite DB at path and returns an un-migrated Store.
// Call Migrate before use.
func Open(path, migrDir string) (model.Store, error) {
	db, err := sql.Open(DriverName, path)
	if err != nil {
		return nil, fmt.Errorf("store.Open: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite WAL: one writer, serialized
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store.Open ping: %w", err)
	}
	for _, pragma := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA foreign_keys = ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store.Open %s: %w", pragma, err)
		}
	}
	return &sqliteStore{db: db, q: sqlc.New(db), migrDir: migrDir}, nil
}

func (s *sqliteStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}

func (s *sqliteStore) Migrate(ctx context.Context) error {
	return runMigrations(s.db, s.migrDir)
}

// ---- RemoteStore ------------------------------------------------------------

func (s *sqliteStore) CreateRemote(ctx context.Context, r *model.Remote) (model.RemoteID, error) {
	row, err := s.q.CreateRemote(ctx, sqlc.CreateRemoteParams{
		Url:                 r.URL,
		NormalizedUrl:       r.NormalizedURL,
		Transport:           string(r.Transport),
		SyncIntervalNs:      r.SyncIntervalNS,
		StalenessBudgetNs:   r.StalenessBudgetNS,
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

func (s *sqliteStore) GetRemote(ctx context.Context, id model.RemoteID) (*model.Remote, error) {
	row, err := s.q.GetRemote(ctx, int64(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("GetRemote %d: %w", id, model.ErrNotFound)
		}
		return nil, fmt.Errorf("GetRemote %d: %w", id, err)
	}
	m, err := remoteFromRow(row)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *sqliteStore) GetRemoteByURL(ctx context.Context, normalizedURL string) (*model.Remote, error) {
	row, err := s.q.GetRemoteByURL(ctx, normalizedURL)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("GetRemoteByURL %q: %w", normalizedURL, model.ErrNotFound)
		}
		return nil, fmt.Errorf("GetRemoteByURL: %w", err)
	}
	m, err := remoteFromRow(row)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *sqliteStore) ListRemotes(ctx context.Context, limit int, cursor int64) ([]model.Remote, int64, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.q.ListRemotes(ctx, sqlc.ListRemotesParams{
		ID:    cursor,
		Limit: int64(limit),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("ListRemotes: %w", err)
	}
	out := make([]model.Remote, 0, len(rows))
	var nextCursor int64
	for _, r := range rows {
		m, err := remoteFromRow(r)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, m)
		if int64(r.ID) > nextCursor {
			nextCursor = int64(r.ID)
		}
	}
	return out, nextCursor, nil
}

func (s *sqliteStore) UpdateRemote(ctx context.Context, r *model.Remote) error {
	_, err := s.q.UpdateRemote(ctx, sqlc.UpdateRemoteParams{
		Url:                 r.URL,
		NormalizedUrl:       r.NormalizedURL,
		Transport:           string(r.Transport),
		SyncIntervalNs:      r.SyncIntervalNS,
		StalenessBudgetNs:   r.StalenessBudgetNS,
		TaintAnyTagDeletion: boolToInt(r.TaintAnyTagDeletion),
		HashAlgo:            nullStringInterface(hashAlgoPtr(r.HashAlgo)),
		Status:              string(r.Status),
		LastOkNs:            r.LastOkNS,
		LastErr:             r.LastErr,
		ConsecutiveFailures: int64(r.ConsecutiveFailures),
		ChainHeadHash:       r.ChainHeadHash,
		ChainLen:            r.ChainLen,
		RemovedAtNs:         nullInt64Interface(r.RemovedAtNS),
		UpdatedAtNs:         r.UpdatedAtNS,
		ID:                  int64(r.ID),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("UpdateRemote %d: %w", r.ID, model.ErrNotFound)
		}
		return fmt.Errorf("UpdateRemote %d: %w", r.ID, err)
	}
	return nil
}

func (s *sqliteStore) SoftDeleteRemote(ctx context.Context, id model.RemoteID, atNS int64) error {
	if err := s.q.SoftDeleteRemote(ctx, sqlc.SoftDeleteRemoteParams{
		RemovedAtNs: atNS,
		UpdatedAtNs: atNS,
		ID:          int64(id),
	}); err != nil {
		return fmt.Errorf("SoftDeleteRemote %d: %w", id, err)
	}
	return nil
}

func (s *sqliteStore) SelectDueRemotes(ctx context.Context, nowNs int64, limit int) ([]model.Remote, error) {
	rows, err := s.q.SelectDueRemotes(ctx, sqlc.SelectDueRemotesParams{
		LastOkNs: nowNs,
		Limit:    int64(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("SelectDueRemotes: %w", err)
	}
	out := make([]model.Remote, 0, len(rows))
	for _, r := range rows {
		m, err := remoteFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func (s *sqliteStore) SetRemoteHealth(ctx context.Context, id model.RemoteID, status model.RemoteStatus, lastErr string, lastOkNS int64) error {
	if err := s.q.SetRemoteHealth(ctx, sqlc.SetRemoteHealthParams{
		Status:      string(status),
		LastErr:     lastErr,
		LastOkNs:    lastOkNS,
		UpdatedAtNs: nowNS(),
		ID:          int64(id),
	}); err != nil {
		return fmt.Errorf("SetRemoteHealth %d: %w", id, err)
	}
	return nil
}

// ---- RefStore ---------------------------------------------------------------

func (s *sqliteStore) GetRef(ctx context.Context, remoteID model.RemoteID, tagName string) (*model.Ref, error) {
	row, err := s.q.GetRef(ctx, sqlc.GetRefParams{
		RemoteID: int64(remoteID),
		TagName:  tagName,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("GetRef remote=%d name=%q: %w", remoteID, tagName, model.ErrNotFound)
		}
		return nil, fmt.Errorf("GetRef: %w", err)
	}
	ref, err := refFromRow(row, model.SHA1)
	if err != nil {
		return nil, err
	}
	return &ref, nil
}

func (s *sqliteStore) ListTags(ctx context.Context, remoteID model.RemoteID) ([]model.Ref, error) {
	rawRows, err := s.q.ListTags(ctx, int64(remoteID))
	if err != nil {
		return nil, fmt.Errorf("ListTags: %w", err)
	}
	out := make([]model.Ref, 0, len(rawRows))
	for _, r := range rawRows {
		ref, err := refFromRow(r, model.SHA1)
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}

func (s *sqliteStore) SetRefTaint(ctx context.Context, refID model.RefID, firstNS int64) error {
	if err := s.q.SetRefTaint(ctx, sqlc.SetRefTaintParams{
		TaintFirstNs: firstNS,
		ID:           int64(refID),
	}); err != nil {
		return fmt.Errorf("SetRefTaint %d: %w", refID, err)
	}
	return nil
}

// ---- ObservationStore -------------------------------------------------------

func (s *sqliteStore) GetChainHead(ctx context.Context, remoteID model.RemoteID) ([]byte, int64, error) {
	row, err := s.q.GetChainHead(ctx, int64(remoteID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, fmt.Errorf("GetChainHead %d: %w", remoteID, model.ErrNotFound)
		}
		return nil, 0, fmt.Errorf("GetChainHead %d: %w", remoteID, err)
	}
	return row.ChainHeadHash, row.ChainLen, nil
}

func (s *sqliteStore) LatestObservationForRef(ctx context.Context, refID model.RefID) (*model.ObservationProof, error) {
	row, err := s.q.LatestObservationForRef(ctx, int64(refID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("LatestObservationForRef %d: %w", refID, model.ErrNotFound)
		}
		return nil, fmt.Errorf("LatestObservationForRef %d: %w", refID, err)
	}
	return &model.ObservationProof{
		RemoteID: model.RemoteID(row.RemoteID),
		Seq:      model.Seq(row.Seq),
		RowHash:  row.RowHash,
	}, nil
}

func (s *sqliteStore) ReplayObservations(ctx context.Context, remoteID model.RemoteID, fromSeq model.Seq, limit int) ([]model.Observation, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.q.ReplayObservations(ctx, sqlc.ReplayObservationsParams{
		RemoteID: int64(remoteID),
		Seq:      int64(fromSeq),
		Limit:    int64(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("ReplayObservations: %w", err)
	}
	out := make([]model.Observation, 0, len(rows))
	for _, r := range rows {
		obs := model.Observation{
			ID:           r.ID,
			RemoteID:     model.RemoteID(r.RemoteID),
			RefID:        model.RefID(r.RefID),
			SyncID:       model.SyncID(toInt64(r.SyncID)),
			Seq:          model.Seq(r.Seq),
			EventType:    model.ObservationEventType(r.EventType),
			ObservedAtNS: r.ObservedAtNs,
			PrevHash:     r.PrevHash,
			RowHash:      r.RowHash,
		}
		if b := toBytes(r.PrevOid); len(b) > 0 {
			obs.PrevOID = model.OIDFromRaw(b, model.SHA1)
		}
		if b := toBytes(r.NewOid); len(b) > 0 {
			obs.NewOID = model.OIDFromRaw(b, model.SHA1)
		}
		if b := toBytes(r.PrevPeeledOid); len(b) > 0 {
			obs.PrevPeeledOID = model.OIDFromRaw(b, model.SHA1)
		}
		if b := toBytes(r.NewPeeledOid); len(b) > 0 {
			obs.NewPeeledOID = model.OIDFromRaw(b, model.SHA1)
		}
		if r.CanonicalMeta != nil {
			obs.CanonicalMeta = toString(r.CanonicalMeta)
		}
		out = append(out, obs)
	}
	return out, nil
}

// ---- TaintStore -------------------------------------------------------------

func (s *sqliteStore) AppendTaintEvent(ctx context.Context, e *model.TaintEvent) (int64, error) {
	var observationID interface{}
	if e.ObservationID != nil {
		observationID = *e.ObservationID
	}
	id, err := s.q.InsertTaintEvent(ctx, sqlc.InsertTaintEventParams{
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
		return 0, fmt.Errorf("AppendTaintEvent: %w", err)
	}
	return id, nil
}

func (s *sqliteStore) ListTaintEvents(ctx context.Context, remoteID model.RemoteID, limit int, cursor int64) ([]model.TaintEvent, int64, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.q.ListTaintEvents(ctx, sqlc.ListTaintEventsParams{
		RemoteID: int64(remoteID),
		ID:       cursor,
		Limit:    int64(limit),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("ListTaintEvents: %w", err)
	}
	out := make([]model.TaintEvent, 0, len(rows))
	var nextCursor int64
	for _, r := range rows {
		e := taintEventFromRow(r)
		out = append(out, e)
		if r.ID > nextCursor {
			nextCursor = r.ID
		}
	}
	return out, nextCursor, nil
}

func (s *sqliteStore) AckTaintEvent(ctx context.Context, id int64, by, note string, atNS int64) error {
	if err := s.q.AckTaintEvent(ctx, sqlc.AckTaintEventParams{
		AckedAtNs: int64(atNS),
		AckedBy:   by,
		AckNote:   note,
		ID:        id,
	}); err != nil {
		return fmt.Errorf("AckTaintEvent %d: %w", id, err)
	}
	return nil
}

// ---- SyncStore --------------------------------------------------------------

func (s *sqliteStore) ListSyncs(ctx context.Context, remoteID model.RemoteID, limit int, cursor int64) ([]model.Sync, int64, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.q.ListSyncs(ctx, sqlc.ListSyncsParams{
		RemoteID: int64(remoteID),
		ID:       cursor,
		Limit:    int64(limit),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("ListSyncs: %w", err)
	}
	out := make([]model.Sync, 0, len(rows))
	var nextCursor int64
	for _, r := range rows {
		sy := syncFromRow(r)
		out = append(out, sy)
		if r.ID > nextCursor {
			nextCursor = r.ID
		}
	}
	return out, nextCursor, nil
}

// ---- Lock seam --------------------------------------------------------------

const upsertLeaseSQL = `
INSERT INTO remote_lease (remote_id, holder, acquired_at_ns, expires_at_ns)
VALUES (?, ?, ?, ?)
ON CONFLICT(remote_id) DO UPDATE SET
  holder         = excluded.holder,
  acquired_at_ns = excluded.acquired_at_ns,
  expires_at_ns  = excluded.expires_at_ns
WHERE remote_lease.expires_at_ns < ?
`

func (s *sqliteStore) TryAcquireLease(ctx context.Context, remoteID model.RemoteID, holder string, nowNs, expiresNS int64) (ok bool, chainHead []byte, err error) {
	headRow, err := s.q.GetRemoteChainHead(ctx, int64(remoteID))
	if err != nil {
		return false, nil, fmt.Errorf("TryAcquireLease get chain head: %w", err)
	}
	result, err := s.db.ExecContext(ctx, upsertLeaseSQL,
		int64(remoteID), holder, nowNs, expiresNS, nowNs,
	)
	if err != nil {
		return false, nil, fmt.Errorf("TryAcquireLease upsert: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, nil, fmt.Errorf("TryAcquireLease rows: %w", err)
	}
	if rows == 0 {
		return false, nil, nil
	}
	return true, headRow.ChainHeadHash, nil
}

func (s *sqliteStore) ReleaseLeaseCAS(ctx context.Context, remoteID model.RemoteID, holder string, witness, newHead []byte, newLen int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("ReleaseLeaseCAS begin: %w", err)
	}
	q := sqlc.New(tx)

	headRow, err := q.GetRemoteChainHead(ctx, int64(remoteID))
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("ReleaseLeaseCAS get head: %w", err)
	}

	currentHead := headRow.ChainHeadHash
	switch {
	case bytesEqual(currentHead, witness):
		rows, err := q.AdvanceRemoteChainHead(ctx, sqlc.AdvanceRemoteChainHeadParams{
			ChainHeadHash:   newHead,
			ChainLen:        newLen,
			ID:              int64(remoteID),
			ChainHeadHash_2: witness,
			ChainLen_2:      headRow.ChainLen,
		})
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("ReleaseLeaseCAS advance: %w", err)
		}
		if rows != 1 {
			_ = tx.Rollback()
			return fmt.Errorf("ReleaseLeaseCAS advance rows=%d: %w", rows, model.ErrChainCAS)
		}
	case bytesEqual(currentHead, newHead):
		// Chain was already advanced by AppendObservation inside WithTx.
	default:
		_ = tx.Rollback()
		return fmt.Errorf("ReleaseLeaseCAS: %w", model.ErrChainCAS)
	}

	if err := q.DeleteRemoteLease(ctx, sqlc.DeleteRemoteLeaseParams{
		RemoteID: int64(remoteID),
		Holder:   holder,
	}); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("ReleaseLeaseCAS delete lease: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ReleaseLeaseCAS commit: %w", err)
	}
	return nil
}

// ---- helpers ----------------------------------------------------------------

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func nullInt64Interface(p *int64) interface{} {
	if p == nil {
		return nil
	}
	return *p
}

func nullStringInterface(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}

func hashAlgoPtr(a *model.HashAlgo) *string {
	if a == nil {
		return nil
	}
	s := string(*a)
	return &s
}

func isUniqueConflict(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "UNIQUE constraint failed") ||
		strings.Contains(s, "unique constraint failed")
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
