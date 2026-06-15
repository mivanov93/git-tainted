package model

import "testing"

func TestTaintReasonValid(t *testing.T) {
	valid := []TaintReason{
		TaintTagOIDChanged, TaintTagDeletedRecreated,
	}
	for _, r := range valid {
		if !r.Valid() {
			t.Errorf("%q should be Valid", r)
		}
	}
	if TaintReason("bogus").Valid() {
		t.Errorf("bogus reason must be invalid")
	}
}

func TestObservationEventTypeValid(t *testing.T) {
	valid := []ObservationEventType{
		EventTagCreated, EventTagOIDChanged, EventTagDeleted, EventTagRecreated,
	}
	for _, e := range valid {
		if !e.Valid() {
			t.Errorf("%q should be Valid", e)
		}
	}
	if ObservationEventType("bogus").Valid() {
		t.Errorf("bogus event must be invalid")
	}
}

func TestVerifyStatusValues(t *testing.T) {
	statuses := []VerifyStatus{
		StatusOK, StatusTainted, StatusMismatch, StatusDoesntExist, StatusNotTracked,
	}
	seen := map[VerifyStatus]bool{}
	for _, s := range statuses {
		if seen[s] {
			t.Errorf("duplicate verify status: %q", s)
		}
		seen[s] = true
	}
}

func TestConfidenceValues(t *testing.T) {
	confs := []Confidence{ConfAuthoritative, ConfStale}
	seen := map[Confidence]bool{}
	for _, c := range confs {
		if seen[c] {
			t.Errorf("duplicate confidence: %q", c)
		}
		seen[c] = true
	}
}

func TestEnumNamespacesDisjoint(t *testing.T) {
	if !TaintReason("tag_oid_changed").Valid() {
		t.Errorf("taint vocab missing tag_oid_changed")
	}
	if !ObservationEventType("tag_oid_changed").Valid() {
		t.Errorf("event vocab missing tag_oid_changed")
	}
	// tag_deleted_recreated is taint-only; it is NOT an observation event.
	if ObservationEventType("tag_deleted_recreated").Valid() {
		t.Errorf("tag_deleted_recreated must not be a valid observation event")
	}
}
