package sync

import (
	"github.com/mivanov93/git-tainted/internal/model"
)

// TagDelta is the classification of one tag between two syncs: the observation
// event to append (empty Event ⇒ no change ⇒ no observation) and an optional
// taint reason.
type TagDelta struct {
	Event model.ObservationEventType
	Taint *model.TaintReason
}

// ClassifyTag classifies a tag's transition. prev is the stored projection
// (nil ⇒ first sighting); now is the fresh ls-remote ref.
// Taint keys on the tag-ref oid (now.OID vs prev.CurrentOID).
func ClassifyTag(prev *model.Ref, now *model.LsRemoteRef) TagDelta {
	if now == nil {
		return TagDelta{}
	}
	if prev == nil || prev.Deleted {
		if prev != nil && prev.Deleted && !prev.CurrentOID.Equal(now.OID) {
			// Seen before, was deleted, now present at different oid → recreated.
			r := model.TaintTagDeletedRecreated
			return TagDelta{Event: model.EventTagRecreated, Taint: &r}
		}
		return TagDelta{Event: model.EventTagCreated}
	}
	if now.OID.Equal(prev.CurrentOID) {
		return TagDelta{} // unchanged tag-object oid
	}
	r := model.TaintTagOIDChanged
	return TagDelta{Event: model.EventTagOIDChanged, Taint: &r}
}

// ClassifyDeletion classifies a tag that vanished from ls-remote.
// A tag deletion taints when taintAnyTagDeletion is true.
func ClassifyDeletion(prev *model.Ref, taintAnyTagDeletion bool) TagDelta {
	if prev == nil {
		return TagDelta{}
	}
	d := TagDelta{Event: model.EventTagDeleted}
	if taintAnyTagDeletion {
		r := model.TaintTagDeletedRecreated
		d.Taint = &r
	}
	return d
}
