package store

import (
	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/store/sqlc"
)

// ---- Remotes ---------------------------------------------------------------

func remoteFromRow(r sqlc.Remote) (model.Remote, error) {
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
	if r.HashAlgo != nil {
		algo := model.HashAlgo(toString(r.HashAlgo))
		m.HashAlgo = &algo
	}
	if r.RemovedAtNs != nil {
		v := toInt64(r.RemovedAtNs)
		m.RemovedAtNS = &v
	}
	return m, nil
}

// ---- Refs ------------------------------------------------------------------

func refFromRow(r sqlc.Ref, algo model.HashAlgo) (model.Ref, error) {
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
	if r.CurrentOid != nil {
		if raw := toBytes(r.CurrentOid); len(raw) > 0 {
			ref.CurrentOID = model.OIDFromRaw(raw, algo)
		}
	}
	if r.CurrentPeeledOid != nil {
		if raw := toBytes(r.CurrentPeeledOid); len(raw) > 0 {
			ref.CurrentPeeledOID = model.OIDFromRaw(raw, algo)
		}
	}
	if r.FirstOid != nil {
		if raw := toBytes(r.FirstOid); len(raw) > 0 {
			ref.FirstOID = model.OIDFromRaw(raw, algo)
		}
	}
	if r.TaintFirstNs != nil {
		v := toInt64(r.TaintFirstNs)
		ref.TaintFirstNS = &v
	}
	return ref, nil
}

// ---- TaintEvents -----------------------------------------------------------

func taintEventFromRow(r sqlc.TaintEvent) model.TaintEvent {
	e := model.TaintEvent{
		ID:           r.ID,
		RemoteID:     model.RemoteID(r.RemoteID),
		RefID:        model.RefID(r.RefID),
		Reason:       model.TaintReason(r.Reason),
		DetectedAtNS: r.DetectedAtNs,
		Detail:       r.Detail,
	}
	if r.ObservationID != nil {
		v := toInt64(r.ObservationID)
		e.ObservationID = &v
	}
	if r.FromOid != nil {
		e.FromOID = model.OIDFromRaw(toBytes(r.FromOid), model.SHA1)
	}
	if r.ToOid != nil {
		e.ToOID = model.OIDFromRaw(toBytes(r.ToOid), model.SHA1)
	}
	if r.AckedAtNs != nil {
		v := toInt64(r.AckedAtNs)
		e.AckedAtNS = &v
	}
	if r.AckedBy != nil {
		e.AckedBy = toString(r.AckedBy)
	}
	if r.AckNote != nil {
		e.AckNote = toString(r.AckNote)
	}
	return e
}

// ---- Syncs -----------------------------------------------------------------

func syncFromRow(r sqlc.Sync) model.Sync {
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
	if r.ChainHeadBefore != nil {
		s.ChainHeadBefore = toBytes(r.ChainHeadBefore)
	}
	if r.ChainHeadAfter != nil {
		s.ChainHeadAfter = toBytes(r.ChainHeadAfter)
	}
	return s
}

// ---- Type helpers for interface{} nullable columns -------------------------

func toInt64(v interface{}) int64 {
	if v == nil {
		return 0
	}
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	case int:
		return int64(x)
	case int32:
		return int64(x)
	default:
		return 0
	}
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func toBytes(v interface{}) []byte {
	if v == nil {
		return nil
	}
	b, _ := v.([]byte)
	return b
}
