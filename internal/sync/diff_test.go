package sync

import (
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
)

func oid(h string) model.OID { return model.MustParseOID(h, model.SHA1) }

const (
	hA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hC = "cccccccccccccccccccccccccccccccccccccccc"
)

func taintPtr(r model.TaintReason) *model.TaintReason { return &r }

func TestClassifyTag(t *testing.T) {
	tests := []struct {
		name      string
		prev      *model.Ref
		now       *model.LsRemoteRef
		wantEvent model.ObservationEventType
		wantTaint *model.TaintReason
	}{
		{
			name:      "new_tag_created",
			prev:      nil,
			now:       &model.LsRemoteRef{Name: "v1.0.0", OID: oid(hA)},
			wantEvent: model.EventTagCreated,
		},
		{
			name:      "tag_oid_changed_taint",
			prev:      &model.Ref{TagName: "v1.0.0", CurrentOID: oid(hA)},
			now:       &model.LsRemoteRef{Name: "v1.0.0", OID: oid(hB)},
			wantEvent: model.EventTagOIDChanged,
			wantTaint: taintPtr(model.TaintTagOIDChanged),
		},
		{
			name:      "tag_unchanged_no_event",
			prev:      &model.Ref{TagName: "v1.0.0", CurrentOID: oid(hA)},
			now:       &model.LsRemoteRef{Name: "v1.0.0", OID: oid(hA)},
			wantEvent: "",
		},
		{
			name:      "tag_recreated_after_deletion",
			prev:      &model.Ref{TagName: "v1.0.0", CurrentOID: oid(hA), Deleted: true},
			now:       &model.LsRemoteRef{Name: "v1.0.0", OID: oid(hB)},
			wantEvent: model.EventTagRecreated,
			wantTaint: taintPtr(model.TaintTagDeletedRecreated),
		},
		{
			name:      "tag_recreated_same_oid_after_deletion",
			prev:      &model.Ref{TagName: "v1.0.0", CurrentOID: oid(hA), Deleted: true},
			now:       &model.LsRemoteRef{Name: "v1.0.0", OID: oid(hA)},
			wantEvent: model.EventTagCreated, // same oid — not a taint
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := ClassifyTag(tc.prev, tc.now)
			if d.Event != tc.wantEvent {
				t.Errorf("event=%q want %q", d.Event, tc.wantEvent)
			}
			if (d.Taint == nil) != (tc.wantTaint == nil) {
				t.Fatalf("taint=%v want %v", d.Taint, tc.wantTaint)
			}
			if tc.wantTaint != nil && *d.Taint != *tc.wantTaint {
				t.Errorf("taint=%q want %q", *d.Taint, *tc.wantTaint)
			}
		})
	}
}

func TestClassifyDeletion(t *testing.T) {
	prev := &model.Ref{TagName: "v1.0.0", CurrentOID: oid(hA)}

	d := ClassifyDeletion(prev, true)
	if d.Event != model.EventTagDeleted {
		t.Errorf("event=%q want tag_deleted", d.Event)
	}
	if d.Taint == nil || *d.Taint != model.TaintTagDeletedRecreated {
		t.Errorf("tag deletion with taintAnyTagDeletion=true must taint tag_deleted_recreated, got %v", d.Taint)
	}

	d2 := ClassifyDeletion(prev, false)
	if d2.Event != model.EventTagDeleted {
		t.Errorf("event=%q want tag_deleted", d2.Event)
	}
	if d2.Taint != nil {
		t.Errorf("tag deletion with taintAnyTagDeletion=false must not taint, got %v", d2.Taint)
	}
}

func TestClassifyDeletionNilPrev(t *testing.T) {
	d := ClassifyDeletion(nil, true)
	if d.Event != "" {
		t.Errorf("nil prev should return empty delta, got %q", d.Event)
	}
}
