package store

import (
	"database/sql"

	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/store/mysqlc"
)

// This file is the MySQL boundary mirror of convert.go. It maps mysqlc row
// structs to model types and converts the dialect-specific nullable column
// representations:
//   - nullable VARBINARY (oid columns) is sql.NullString under sqlc; raw oid
//     bytes round-trip byte-exactly through it (Go strings hold arbitrary
//     bytes, and go-sql-driver/mysql sends them verbatim to a VARBINARY column).
//   - INT columns are int32 (vs SQLite's int64).
//   - nullable BIGINT / TEXT use sql.NullInt64 / sql.NullString.

// ---- Row mappers ------------------------------------------------------------

func remoteFromMySQLRow(r mysqlc.Remote) model.Remote {
	m := model.Remote{
		ID:                  model.RemoteID(r.ID),
		URL:                 r.Url,
		NormalizedURL:       r.NormalizedUrl,
		Transport:           model.Transport(r.Transport),
		SyncIntervalNS:      r.SyncIntervalNs,
		StalenessBudgetNS:   r.StalenessBudgetNs,
		TaintAnyTagDeletion: r.TaintAnyTagDeletion != 0,
		Status:              model.RemoteStatus(r.Status),
		LastOkNS:            r.LastOkNs,
		LastErr:             r.LastErr,
		ConsecutiveFailures: int(r.ConsecutiveFailures),
		ChainHeadHash:       r.ChainHeadHash,
		ChainLen:            r.ChainLen,
		CreatedAtNS:         r.CreatedAtNs,
		UpdatedAtNS:         r.UpdatedAtNs,
	}
	if r.HashAlgo.Valid {
		algo := model.HashAlgo(r.HashAlgo.String)
		m.HashAlgo = &algo
	}
	if r.RemovedAtNs.Valid {
		v := r.RemovedAtNs.Int64
		m.RemovedAtNS = &v
	}
	return m
}

func refFromMySQLRow(r mysqlc.Ref, algo model.HashAlgo) model.Ref {
	ref := model.Ref{
		ID:               model.RefID(r.ID),
		RemoteID:         model.RemoteID(r.RemoteID),
		TagName:          r.TagName,
		IsAnnotatedTag:   r.IsAnnotated != 0,
		FirstSeenNS:      r.FirstSeenNs,
		LastSeenNS:       r.LastSeenNs,
		LastChangedNS:    r.LastChangedNs,
		Deleted:          r.Deleted != 0,
		Tainted:          r.Tainted != 0,
		ObservationCount: r.ObservationCount,
	}
	if raw := bytesFromNullString(r.CurrentOid); len(raw) > 0 {
		ref.CurrentOID = model.OIDFromRaw(raw, algo)
	}
	if raw := bytesFromNullString(r.CurrentPeeledOid); len(raw) > 0 {
		ref.CurrentPeeledOID = model.OIDFromRaw(raw, algo)
	}
	if raw := bytesFromNullString(r.FirstOid); len(raw) > 0 {
		ref.FirstOID = model.OIDFromRaw(raw, algo)
	}
	if r.TaintFirstNs.Valid {
		v := r.TaintFirstNs.Int64
		ref.TaintFirstNS = &v
	}
	return ref
}

func taintEventFromMySQLRow(r mysqlc.TaintEvent) model.TaintEvent {
	e := model.TaintEvent{
		ID:           r.ID,
		RemoteID:     model.RemoteID(r.RemoteID),
		RefID:        model.RefID(r.RefID),
		Reason:       model.TaintReason(r.Reason),
		DetectedAtNS: r.DetectedAtNs,
		Detail:       r.Detail,
	}
	if r.ObservationID.Valid {
		v := r.ObservationID.Int64
		e.ObservationID = &v
	}
	if raw := bytesFromNullString(r.FromOid); len(raw) > 0 {
		e.FromOID = model.OIDFromRaw(raw, model.SHA1)
	}
	if raw := bytesFromNullString(r.ToOid); len(raw) > 0 {
		e.ToOID = model.OIDFromRaw(raw, model.SHA1)
	}
	if r.AckedAtNs.Valid {
		v := r.AckedAtNs.Int64
		e.AckedAtNS = &v
	}
	if r.AckedBy.Valid {
		e.AckedBy = r.AckedBy.String
	}
	if r.AckNote.Valid {
		e.AckNote = r.AckNote.String
	}
	return e
}

func syncFromMySQLRow(r mysqlc.Sync) model.Sync {
	s := model.Sync{
		ID:          model.SyncID(r.ID),
		RemoteID:    model.RemoteID(r.RemoteID),
		Trigger:     model.SyncTrigger(r.Trigger),
		StartedNS:   r.StartedNs,
		FinishedNS:  r.FinishedNs,
		Status:      model.SyncStatus(r.Status),
		TagsSeen:    int(r.TagsSeen),
		TagsChanged: int(r.TagsChanged),
		Error:       r.Error,
	}
	if b := bytesFromNullString(r.ChainHeadBefore); len(b) > 0 {
		s.ChainHeadBefore = b
	}
	if b := bytesFromNullString(r.ChainHeadAfter); len(b) > 0 {
		s.ChainHeadAfter = b
	}
	return s
}

// ---- Nullable conversion helpers --------------------------------------------

// nullStringFromBytes wraps raw bytes as a sql.NullString for a nullable
// VARBINARY parameter: empty/nil → NULL, otherwise the bytes as a string. The
// byte content is preserved exactly (Go strings are arbitrary byte sequences).
func nullStringFromBytes(b []byte) sql.NullString {
	if len(b) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}

// bytesFromNullString returns the raw bytes of a sql.NullString scanned from a
// nullable VARBINARY column: NULL → nil, otherwise the string's bytes.
func bytesFromNullString(ns sql.NullString) []byte {
	if !ns.Valid {
		return nil
	}
	return []byte(ns.String)
}

// nullStringFromStr maps a Go string to sql.NullString: "" → NULL.
func nullStringFromStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// nullStringFromStrPtr maps a *string to sql.NullString: nil → NULL.
func nullStringFromStrPtr(p *string) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *p, Valid: true}
}

// nullInt64 wraps a present int64 as a valid sql.NullInt64.
func nullInt64(v int64) sql.NullInt64 {
	return sql.NullInt64{Int64: v, Valid: true}
}

// nullInt64FromPtr maps a *int64 to sql.NullInt64: nil → NULL.
func nullInt64FromPtr(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}

// boolToInt32 maps a Go bool to the INT (int32) MySQL column representation.
func boolToInt32(b bool) int32 {
	if b {
		return 1
	}
	return 0
}
