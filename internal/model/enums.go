package model

// TaintReason: why a tag became (sticky) tainted. Exactly 2 values.
type TaintReason string

const (
	TaintTagOIDChanged       TaintReason = "tag_oid_changed"
	TaintTagDeletedRecreated TaintReason = "tag_deleted_recreated"
)

// Valid reports whether r is a known taint reason.
func (r TaintReason) Valid() bool {
	return r == TaintTagOIDChanged || r == TaintTagDeletedRecreated
}

// ObservationEventType: what a remote showed at a sync. Exactly 4 values.
type ObservationEventType string

const (
	EventTagCreated    ObservationEventType = "tag_created"
	EventTagOIDChanged ObservationEventType = "tag_oid_changed"
	EventTagDeleted    ObservationEventType = "tag_deleted"
	EventTagRecreated  ObservationEventType = "tag_recreated"
)

// Valid reports whether e is a known observation event type.
func (e ObservationEventType) Valid() bool {
	switch e {
	case EventTagCreated, EventTagOIDChanged, EventTagDeleted, EventTagRecreated:
		return true
	}
	return false
}

// VerifyStatus: the closed 5-value security verdict (§7).
type VerifyStatus string

const (
	StatusOK          VerifyStatus = "ok"
	StatusTainted     VerifyStatus = "tainted"
	StatusMismatch    VerifyStatus = "mismatch"
	StatusDoesntExist VerifyStatus = "doesnt_exist"
	StatusNotTracked  VerifyStatus = "not_tracked"
)

// Confidence: freshness axis, orthogonal to VerifyStatus (§7). 2 values.
type Confidence string

const (
	ConfAuthoritative Confidence = "authoritative"
	ConfStale         Confidence = "stale"
)
