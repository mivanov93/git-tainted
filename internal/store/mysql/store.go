// Package mysql implements model.Store (the second backend) over sqlc-generated
// queries against go-sql-driver/mysql (pure-Go, CGO-free). It mirrors the sqlite
// backend's behavior exactly; the dialect-agnostic chain/migration logic lives
// in the parent internal/store package (store.CanonicalRow, store.RowHash,
// store.RunMigrationsMySQL). The schema lives in db/migrations-mysql, embedded
// into the binary via the db package.
package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"strings"
	"time"

	driver "github.com/go-sql-driver/mysql"

	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/store"
	"github.com/mivanov93/git-tainted/internal/store/mysql/mysqlc"
)

// MySQLDriverName is the database/sql driver name registered by the blank import
// of go-sql-driver/mysql (pure-Go, CGO-free).
const MySQLDriverName = "mysql"

// nowNS returns the current wall time as unix-nanoseconds.
func nowNS() int64 { return time.Now().UnixNano() }

// mysqlStore is the second model.Store implementation, over sqlc-generated
// queries against go-sql-driver/mysql (pure-Go, CGO-free). It mirrors
// sqliteStore exactly in behavior; the only differences are dialect-forced:
//   - sql.Open("mysql", dsn) with a normal (concurrent) connection pool — there
//     is NO SetMaxOpenConns(1). MySQL is concurrent; correctness comes from the
//     per-remote chain_head CAS, not from serializing the pool.
//   - no PRAGMAs.
//   - MySQL lacks RETURNING, so inserts use LastInsertId() and upsert/idempotent
//     rows read their id back via a follow-up SELECT on the unique key.
//   - the canonical row encoding + RowHash come from chain.go unchanged
//     (dialect-agnostic, SHA-256).
type mysqlStore struct {
	db         *sql.DB
	q          *mysqlc.Queries
	migrations fs.FS
}

// Open opens a MySQL-backed Store at dsn, pings it, applies the migrations from
// the provided fs.FS (e.g. db.MySQLMigrations — embedded, so no db/ folder is
// needed on disk), and returns a ready store.
//
// The DSN MUST set multiStatements=true (the migration files are multi-statement
// scripts) and parseTime=false (all timestamps are BIGINT unix-ns, never
// DATETIME — see the unix-ns-everywhere convention). clientFoundRows=true is
// also required so UPDATE ... reports MATCHED rows rather than CHANGED rows: the
// store relies on RowsAffected to distinguish "row not found" (0) from "updated"
// for UpdateRemote and the lease/chain CAS. (The chain CAS always writes a strictly
// new chain_head_hash/chain_len, so matched ⟺ changed there and clientFoundRows
// does not alter CAS-loss detection.)
//
// Example DSN:
//
//	user:pass@tcp(127.0.0.1:3306)/git_tainted?multiStatements=true&parseTime=false&clientFoundRows=true
func Open(dsn string, migrations fs.FS) (model.Store, error) {
	if err := validateMySQLDSN(dsn); err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open(MySQLDriverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("mysql.Open: %w", err)
	}
	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("mysql.Open ping: %w", err)
	}
	s := &mysqlStore{db: sqlDB, q: mysqlc.New(sqlDB), migrations: migrations}
	if err := s.Migrate(context.Background()); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("mysql.Open migrate: %w", err)
	}
	return s, nil
}

// validateMySQLDSN parses the DSN and asserts the params the store relies on:
// multiStatements=true (multi-statement migrations) and clientFoundRows=true
// (matched-rows semantics for UPDATE RowsAffected). It also rejects parseTime=true
// (timestamps are BIGINT ns, not time.Time).
func validateMySQLDSN(dsn string) error {
	cfg, err := driver.ParseDSN(dsn)
	if err != nil {
		return fmt.Errorf("mysql.Open: parse DSN: %w", err)
	}
	if !cfg.MultiStatements {
		return errors.New("mysql.Open: DSN must set multiStatements=true (migrations are multi-statement scripts)")
	}
	if !cfg.ClientFoundRows {
		return errors.New("mysql.Open: DSN must set clientFoundRows=true (UpdateRemote/lease CAS rely on matched-rows RowsAffected)")
	}
	if cfg.ParseTime {
		return errors.New("mysql.Open: DSN must set parseTime=false (timestamps are BIGINT unix-ns, not DATETIME)")
	}
	return nil
}

func (s *mysqlStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *mysqlStore) Close() error                   { return s.db.Close() }

func (s *mysqlStore) Migrate(_ context.Context) error {
	return store.RunMigrationsMySQL(s.db, s.migrations)
}

// ---- RemoteStore ------------------------------------------------------------

func (s *mysqlStore) CreateRemote(ctx context.Context, r *model.Remote) (model.RemoteID, error) {
	id, err := s.q.CreateRemote(ctx, mysqlc.CreateRemoteParams{
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

func (s *mysqlStore) GetRemote(ctx context.Context, id model.RemoteID) (*model.Remote, error) {
	row, err := s.q.GetRemote(ctx, int64(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("GetRemote %d: %w", id, model.ErrNotFound)
		}
		return nil, fmt.Errorf("GetRemote %d: %w", id, err)
	}
	m := remoteFromMySQLRow(row)
	return &m, nil
}

func (s *mysqlStore) GetRemoteByURL(ctx context.Context, normalizedURL string) (*model.Remote, error) {
	row, err := s.q.GetRemoteByURL(ctx, normalizedURL)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("GetRemoteByURL %q: %w", normalizedURL, model.ErrNotFound)
		}
		return nil, fmt.Errorf("GetRemoteByURL: %w", err)
	}
	m := remoteFromMySQLRow(row)
	return &m, nil
}

func (s *mysqlStore) ListRemotes(ctx context.Context, limit int, cursor int64) ([]model.Remote, int64, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.q.ListRemotes(ctx, mysqlc.ListRemotesParams{
		ID:    cursor,
		Limit: int32(limit), //nolint:gosec // bounded page size
	})
	if err != nil {
		return nil, 0, fmt.Errorf("ListRemotes: %w", err)
	}
	out := make([]model.Remote, 0, len(rows))
	var nextCursor int64
	for _, r := range rows {
		m := remoteFromMySQLRow(r)
		out = append(out, m)
		if r.ID > nextCursor {
			nextCursor = r.ID
		}
	}
	return out, nextCursor, nil
}

func (s *mysqlStore) CountAllRemotes(ctx context.Context) (int64, error) {
	n, err := s.q.CountAllRemotes(ctx)
	if err != nil {
		return 0, fmt.Errorf("CountAllRemotes: %w", err)
	}
	return n, nil
}

func (s *mysqlStore) UpdateRemote(ctx context.Context, r *model.Remote) error {
	n, err := s.q.UpdateRemote(ctx, mysqlc.UpdateRemoteParams{
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
		UpdatedAtNs:         r.UpdatedAtNS,
		ID:                  int64(r.ID),
	})
	if err != nil {
		return fmt.Errorf("UpdateRemote %d: %w", r.ID, err)
	}
	// clientFoundRows=true ⇒ n is the MATCHED-row count; 0 means no such id.
	if n == 0 {
		return fmt.Errorf("UpdateRemote %d: %w", r.ID, model.ErrNotFound)
	}
	return nil
}

func (s *mysqlStore) SoftDeleteRemote(ctx context.Context, id model.RemoteID, atNS int64) error {
	if err := s.q.SoftDeleteRemote(ctx, mysqlc.SoftDeleteRemoteParams{
		RemovedAtNs: nullInt64(atNS),
		UpdatedAtNs: atNS,
		ID:          int64(id),
	}); err != nil {
		return fmt.Errorf("SoftDeleteRemote %d: %w", id, err)
	}
	return nil
}

func (s *mysqlStore) SelectDueRemotes(ctx context.Context, nowNs int64, limit int) ([]model.Remote, error) {
	rows, err := s.q.SelectDueRemotes(ctx, mysqlc.SelectDueRemotesParams{
		LastOkNs: nowNs,
		Limit:    int32(limit), //nolint:gosec // bounded batch size
	})
	if err != nil {
		return nil, fmt.Errorf("SelectDueRemotes: %w", err)
	}
	out := make([]model.Remote, 0, len(rows))
	for _, r := range rows {
		m := remoteFromMySQLRow(r)
		out = append(out, m)
	}
	return out, nil
}

func (s *mysqlStore) SetRemoteHealth(ctx context.Context, id model.RemoteID, status model.RemoteStatus, lastErr string, lastOkNS int64) error {
	if err := s.q.SetRemoteHealth(ctx, mysqlc.SetRemoteHealthParams{
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

func (s *mysqlStore) GetRef(ctx context.Context, remoteID model.RemoteID, tagName string) (*model.Ref, error) {
	row, err := s.q.GetRef(ctx, mysqlc.GetRefParams{
		RemoteID: int64(remoteID),
		TagName:  tagName,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("GetRef remote=%d name=%q: %w", remoteID, tagName, model.ErrNotFound)
		}
		return nil, fmt.Errorf("GetRef: %w", err)
	}
	ref := refFromMySQLRow(row)
	return &ref, nil
}

func (s *mysqlStore) ListTags(ctx context.Context, remoteID model.RemoteID) ([]model.Ref, error) {
	rows, err := s.q.ListTags(ctx, int64(remoteID))
	if err != nil {
		return nil, fmt.Errorf("ListTags: %w", err)
	}
	out := make([]model.Ref, 0, len(rows))
	for _, r := range rows {
		out = append(out, refFromMySQLRow(r))
	}
	return out, nil
}

func (s *mysqlStore) SetRefTaint(ctx context.Context, refID model.RefID, firstNS int64) error {
	if err := s.q.SetRefTaint(ctx, mysqlc.SetRefTaintParams{
		TaintFirstNs: nullInt64(firstNS),
		ID:           int64(refID),
	}); err != nil {
		return fmt.Errorf("SetRefTaint %d: %w", refID, err)
	}
	return nil
}

// ---- ObservationStore -------------------------------------------------------

func (s *mysqlStore) GetChainHead(ctx context.Context, remoteID model.RemoteID) ([]byte, int64, error) {
	row, err := s.q.GetChainHead(ctx, int64(remoteID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, fmt.Errorf("GetChainHead %d: %w", remoteID, model.ErrNotFound)
		}
		return nil, 0, fmt.Errorf("GetChainHead %d: %w", remoteID, err)
	}
	return row.ChainHeadHash, row.ChainLen, nil
}

func (s *mysqlStore) LatestObservationForRef(ctx context.Context, refID model.RefID) (*model.ObservationProof, error) {
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

func (s *mysqlStore) ReplayObservations(ctx context.Context, remoteID model.RemoteID, fromSeq model.Seq, limit int) ([]model.Observation, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.q.ReplayObservations(ctx, mysqlc.ReplayObservationsParams{
		RemoteID: int64(remoteID),
		Seq:      int64(fromSeq),
		Limit:    int32(limit), //nolint:gosec // bounded batch size
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
			SyncID:       model.SyncID(r.SyncID),
			Seq:          model.Seq(r.Seq),
			EventType:    model.ObservationEventType(r.EventType),
			ObservedAtNS: r.ObservedAtNs,
			PrevHash:     r.PrevHash,
			RowHash:      r.RowHash,
		}
		if b := bytesFromNullString(r.PrevOid); len(b) > 0 {
			obs.PrevOID = model.OIDFromRaw(b)
		}
		if b := bytesFromNullString(r.NewOid); len(b) > 0 {
			obs.NewOID = model.OIDFromRaw(b)
		}
		if b := bytesFromNullString(r.PrevPeeledOid); len(b) > 0 {
			obs.PrevPeeledOID = model.OIDFromRaw(b)
		}
		if b := bytesFromNullString(r.NewPeeledOid); len(b) > 0 {
			obs.NewPeeledOID = model.OIDFromRaw(b)
		}
		if r.CanonicalMeta.Valid {
			obs.CanonicalMeta = r.CanonicalMeta.String
		}
		out = append(out, obs)
	}
	return out, nil
}

// ---- TaintStore -------------------------------------------------------------

func (s *mysqlStore) AppendTaintEvent(ctx context.Context, e *model.TaintEvent) (int64, error) {
	return insertTaintEventMySQL(ctx, s.q, e)
}

func (s *mysqlStore) ListTaintEvents(ctx context.Context, remoteID model.RemoteID, limit int, cursor int64) ([]model.TaintEvent, int64, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.q.ListTaintEvents(ctx, mysqlc.ListTaintEventsParams{
		RemoteID: int64(remoteID),
		ID:       cursor,
		Limit:    int32(limit), //nolint:gosec // bounded page size
	})
	if err != nil {
		return nil, 0, fmt.Errorf("ListTaintEvents: %w", err)
	}
	out := make([]model.TaintEvent, 0, len(rows))
	var nextCursor int64
	for _, r := range rows {
		out = append(out, taintEventFromMySQLRow(r))
		if r.ID > nextCursor {
			nextCursor = r.ID
		}
	}
	return out, nextCursor, nil
}

func (s *mysqlStore) AckTaintEvent(ctx context.Context, id int64, by, note string, atNS int64) error {
	if err := s.q.AckTaintEvent(ctx, mysqlc.AckTaintEventParams{
		AckedAtNs: nullInt64(atNS),
		AckedBy:   nullStringFromStr(by),
		AckNote:   nullStringFromStr(note),
		ID:        id,
	}); err != nil {
		return fmt.Errorf("AckTaintEvent %d: %w", id, err)
	}
	return nil
}

// ---- SyncStore --------------------------------------------------------------

func (s *mysqlStore) ListSyncs(ctx context.Context, remoteID model.RemoteID, limit int, cursor int64) ([]model.Sync, int64, error) {
	if limit <= 0 {
		limit = 100
	}
	if cursor <= 0 {
		cursor = math.MaxInt64 // 0 = first page (from newest); cursor is an exclusive upper bound on id
	}
	rows, err := s.q.ListSyncs(ctx, mysqlc.ListSyncsParams{
		RemoteID: int64(remoteID),
		ID:       cursor,
		Limit:    int32(limit), //nolint:gosec // bounded page size
	})
	if err != nil {
		return nil, 0, fmt.Errorf("ListSyncs: %w", err)
	}
	out := make([]model.Sync, 0, len(rows))
	for _, r := range rows {
		out = append(out, syncFromMySQLRow(r))
	}
	// Newest-first: the last row carries the smallest id. Only a full page can have
	// an older page after it; signal "no more" with 0 otherwise.
	var nextCursor int64
	if len(rows) == limit && len(out) > 0 {
		nextCursor = int64(out[len(out)-1].ID)
	}
	return out, nextCursor, nil
}

// ---- Lock seam --------------------------------------------------------------

// upsertLeaseMySQLSQL mirrors upsertLeaseSQL but in MySQL syntax: the freshness
// predicate (only steal an expired lease) is expressed with the standard
// INSERT ... ON DUPLICATE KEY UPDATE + a guarded column assignment. MySQL has no
// row-level WHERE on ON DUPLICATE KEY UPDATE, so each column is conditionally
// kept-or-replaced via IF(expires_at_ns < ?, new, old): when the existing lease
// is still live, every column keeps its current value (a no-op upsert) and
// RowsAffected reports 0 changed rows; when it is expired, all columns are
// replaced and a row changes. clientFoundRows=true would make a matched no-op
// report 1, so this lease path uses a dedicated *sql.DB read-back of the holder
// to decide success rather than RowsAffected (see TryAcquireLease).
const upsertLeaseMySQLSQL = `
INSERT INTO remote_lease (remote_id, holder, acquired_at_ns, expires_at_ns)
VALUES (?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
  holder         = IF(expires_at_ns < ?, VALUES(holder),         holder),
  acquired_at_ns = IF(expires_at_ns < ?, VALUES(acquired_at_ns), acquired_at_ns),
  expires_at_ns  = IF(expires_at_ns < ?, VALUES(expires_at_ns),  expires_at_ns)
`

func (s *mysqlStore) TryAcquireLease(ctx context.Context, remoteID model.RemoteID, holder string, nowNs, expiresNS int64) (ok bool, chainHead []byte, err error) {
	// Read the chain head first (also asserts the remote exists).
	headRow, err := s.q.GetRemoteChainHead(ctx, int64(remoteID))
	if err != nil {
		return false, nil, fmt.Errorf("TryAcquireLease get chain head: %w", err)
	}
	// Upsert: insert if absent, or overwrite ONLY if the existing lease expired.
	if _, err := s.db.ExecContext(ctx, upsertLeaseMySQLSQL,
		int64(remoteID), holder, nowNs, expiresNS,
		nowNs, nowNs, nowNs,
	); err != nil {
		return false, nil, fmt.Errorf("TryAcquireLease upsert: %w", err)
	}
	// Success ⟺ the row now records THIS holder with our expiry. Because two
	// holders could both upsert, the authoritative check is a read-back: we won
	// iff the persisted holder == our holder AND expires == our expiry.
	leaseRow, err := s.q.GetRemoteLease(ctx, int64(remoteID))
	if err != nil {
		return false, nil, fmt.Errorf("TryAcquireLease read-back: %w", err)
	}
	if leaseRow.Holder != holder || leaseRow.ExpiresAtNs != expiresNS {
		return false, nil, nil
	}
	return true, headRow.ChainHeadHash, nil
}

func (s *mysqlStore) ReleaseLeaseCAS(ctx context.Context, remoteID model.RemoteID, holder string, witness, newHead []byte, newLen int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("ReleaseLeaseCAS begin: %w", err)
	}
	q := mysqlc.New(tx)

	// Lease-ownership assertion (the non-serialized-store carryover): a MySQL
	// store has a concurrent pool, so a release must only succeed for the lease
	// THIS holder owns. If the row is gone or held by someone else, refuse.
	leaseRow, err := q.GetRemoteLease(ctx, int64(remoteID))
	if err != nil {
		_ = tx.Rollback()
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("ReleaseLeaseCAS: lease for remote %d not held: %w", remoteID, model.ErrLeaseLost)
		}
		return fmt.Errorf("ReleaseLeaseCAS get lease: %w", err)
	}
	if leaseRow.Holder != holder {
		_ = tx.Rollback()
		return fmt.Errorf("ReleaseLeaseCAS: lease for remote %d held by %q not %q: %w",
			remoteID, leaseRow.Holder, holder, model.ErrLeaseLost)
	}

	headRow, err := q.GetRemoteChainHead(ctx, int64(remoteID))
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("ReleaseLeaseCAS get head: %w", err)
	}

	currentHead := headRow.ChainHeadHash
	switch {
	case bytesEqual(currentHead, witness):
		rows, err := q.AdvanceRemoteChainHead(ctx, mysqlc.AdvanceRemoteChainHeadParams{
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

	if err := q.DeleteRemoteLease(ctx, mysqlc.DeleteRemoteLeaseParams{
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

// isMySQLUniqueConflict reports whether err is a MySQL duplicate-key error
// (error number 1062, ER_DUP_ENTRY).
func isMySQLUniqueConflict(err error) bool {
	if err == nil {
		return false
	}
	var myErr *driver.MySQLError
	if errors.As(err, &myErr) {
		return myErr.Number == 1062
	}
	// Fallback for wrapped/string errors.
	return strings.Contains(err.Error(), "Error 1062") ||
		strings.Contains(err.Error(), "Duplicate entry")
}

// hashAlgoPtr maps a *model.HashAlgo to a *string for the nullable hash_algo
// column (nil → NULL).
func hashAlgoPtr(a *model.HashAlgo) *string {
	if a == nil {
		return nil
	}
	s := string(*a)
	return &s
}

// bytesEqual reports whether two byte slices are equal (used by the chain-head
// CAS comparisons in ReleaseLeaseCAS).
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

// Verify mysqlStore satisfies model.Store at compile time.
var _ model.Store = (*mysqlStore)(nil)
