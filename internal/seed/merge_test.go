package seed

import (
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
)

// --- test fixtures ----------------------------------------------------------

const (
	// sha1 (40-hex) and sha256 (64-hex) sample oids.
	oidA  = "1111111111111111111111111111111111111111"
	oidB  = "2222222222222222222222222222222222222222"
	oidC  = "3333333333333333333333333333333333333333"
	oid64 = "1111111111111111111111111111111111111111111111111111111111111111"
)

func sp(s string) *string { return &s }
func bp(b bool) *bool     { return &b }
func ip(i int64) *int64   { return &i }

// peer builds a peerRemoteView for one peer reporting one remote with the given tags/events.
func peerView(peer, normURL string, tags []wireTag, events []wireTaintEvent) peerRemoteView {
	return peerRemoteView{
		peer: peer,
		remote: wireRemote{
			ID: 1, URL: normURL, NormalizedURL: normURL,
			Transport: "https", TaintAnyTagDeletion: true,
		},
		tags:        tags,
		taintEvents: events,
	}
}

// tag builds a wireTag with a first_oid baseline (clean, lightweight by default).
func tag(id int64, name, firstOID, currentOID string) wireTag {
	return wireTag{
		ID: id, RemoteID: 1, TagName: name,
		FirstOID: sp(firstOID), CurrentOID: sp(currentOID), CurrentPeeledOID: sp(currentOID),
		IsAnnotated: bp(false), FirstSeenNS: 1000, LastSeenNS: 2000,
	}
}

// --- quorum agreement / disagreement ---------------------------------------

func TestMerge_Agreement_AdoptsBaseline(t *testing.T) {
	const url = "https://example.com/owner/repo"
	views := []peerRemoteView{
		peerView("p1", url, []wireTag{tag(1, "v1", oidA, oidA)}, nil),
		peerView("p2", url, []wireTag{tag(1, "v1", oidA, oidA)}, nil),
	}
	res := mergeQuorum(map[string][]peerRemoteView{url: views}, 2)
	if len(res.remotes) != 1 {
		t.Fatalf("want 1 adopted remote, got %d", len(res.remotes))
	}
	mr := res.remotes[0]
	if len(mr.tags) != 1 {
		t.Fatalf("want 1 adopted tag, got %d (quarantined=%d)", len(mr.tags), res.quarantinedTags)
	}
	if mr.tags[0].firstOID.Hex() != oidA {
		t.Errorf("first_oid = %s, want %s", mr.tags[0].firstOID.Hex(), oidA)
	}
	if mr.tags[0].tainted {
		t.Error("tag must not be tainted (no peer reported taint)")
	}
}

func TestMerge_SubQuorumDisagreement_Quarantines(t *testing.T) {
	const url = "https://example.com/owner/repo"
	// Two peers disagree on first_oid under N=2 → no value reaches quorum → quarantine.
	views := []peerRemoteView{
		peerView("p1", url, []wireTag{tag(1, "v1", oidA, oidA)}, nil),
		peerView("p2", url, []wireTag{tag(1, "v1", oidB, oidB)}, nil),
	}
	res := mergeQuorum(map[string][]peerRemoteView{url: views}, 2)
	if len(res.remotes) != 1 {
		t.Fatalf("remote itself should still be adopted (2 peers report it); got %d", len(res.remotes))
	}
	if len(res.remotes[0].tags) != 0 {
		t.Errorf("disagreeing tag must be quarantined, got %d adopted", len(res.remotes[0].tags))
	}
	if res.quarantinedTags != 1 {
		t.Errorf("quarantinedTags = %d, want 1", res.quarantinedTags)
	}
	if len(res.quarantineLogs) != 1 || res.quarantineLogs[0].tagName != "v1" {
		t.Errorf("expected a quarantine log for v1, got %+v", res.quarantineLogs)
	}
}

func TestMerge_RemoteBelowQuorum_NotAdopted(t *testing.T) {
	const url = "https://example.com/owner/repo"
	// Only one peer reports the remote under N=2 → remote not adopted at all.
	views := []peerRemoteView{
		peerView("p1", url, []wireTag{tag(1, "v1", oidA, oidA)}, nil),
	}
	res := mergeQuorum(map[string][]peerRemoteView{url: views}, 2)
	if len(res.remotes) != 0 {
		t.Errorf("remote with 1<2 peers must not be adopted, got %d", len(res.remotes))
	}
}

// --- quorum-gated taint (M1) ------------------------------------------------

func TestMerge_QuorumGatedTaint_AdoptedAtQuorum(t *testing.T) {
	const url = "https://example.com/owner/repo"
	// v1 moved A→B; both peers agree first_oid=A, both tainted, both have the event.
	mkTainted := func(peer string) peerRemoteView {
		tg := tag(1, "v1", oidA, oidB)
		tg.Tainted = true
		tg.TaintFirstNS = ip(5000)
		ev := wireTaintEvent{ID: 1, RemoteID: 1, RefID: 1, Reason: "tag_oid_changed", FromOID: sp(oidA), ToOID: sp(oidB), DetectedAtNS: 5000}
		return peerView(peer, url, []wireTag{tg}, []wireTaintEvent{ev})
	}
	res := mergeQuorum(map[string][]peerRemoteView{url: {mkTainted("p1"), mkTainted("p2")}}, 2)
	if len(res.remotes) != 1 || len(res.remotes[0].tags) != 1 {
		t.Fatalf("expected 1 remote/1 tag, got remotes=%d", len(res.remotes))
	}
	mt := res.remotes[0].tags[0]
	if !mt.tainted {
		t.Fatal("tag should be tainted (2/2 peers agree)")
	}
	if mt.taintFirstNS == nil || *mt.taintFirstNS != 5000 {
		t.Errorf("taintFirstNS = %v, want 5000", mt.taintFirstNS)
	}
	if len(mt.events) != 1 || mt.events[0].eventType != model.EventTagOIDChanged {
		t.Errorf("want 1 tag_oid_changed event, got %+v", mt.events)
	}
	if mt.events[0].taintReason == nil || *mt.events[0].taintReason != model.TaintTagOIDChanged {
		t.Errorf("event taint reason wrong: %+v", mt.events[0].taintReason)
	}
}

func TestMerge_FabricatedTaint_SubQuorum_NotAdopted(t *testing.T) {
	const url = "https://example.com/owner/repo"
	// p1 fabricates a taint (A→C); p2 and p3 see a clean v1 at A. N=2.
	// first_oid=A reaches quorum (3/3). Taint reported by only 1<2 → NOT adopted.
	clean := func(peer string) peerRemoteView {
		return peerView(peer, url, []wireTag{tag(1, "v1", oidA, oidA)}, nil)
	}
	tg := tag(1, "v1", oidA, oidC)
	tg.Tainted = true
	tg.TaintFirstNS = ip(9000)
	badEv := wireTaintEvent{ID: 1, RemoteID: 1, RefID: 1, Reason: "tag_oid_changed", FromOID: sp(oidA), ToOID: sp(oidC), DetectedAtNS: 9000}
	poison := peerView("p1", url, []wireTag{tg}, []wireTaintEvent{badEv})

	res := mergeQuorum(map[string][]peerRemoteView{url: {poison, clean("p2"), clean("p3")}}, 2)
	if len(res.remotes) != 1 || len(res.remotes[0].tags) != 1 {
		t.Fatalf("expected the tag to be adopted clean (first_oid quorum holds); got remotes=%d", len(res.remotes))
	}
	mt := res.remotes[0].tags[0]
	if mt.tainted {
		t.Error("sub-quorum fabricated taint must NOT be adopted (M1)")
	}
	if len(mt.events) != 0 {
		t.Errorf("no taint events should be written for a dropped sub-quorum taint, got %d", len(mt.events))
	}
	if mt.firstOID.Hex() != oidA {
		t.Errorf("first_oid should still be the agreed A, got %s", mt.firstOID.Hex())
	}
}

// --- taint-event union / dedupe / order -------------------------------------

func TestMerge_TaintEventUnionDedupeOrder(t *testing.T) {
	const url = "https://example.com/owner/repo"
	// v1: A→B (t=5000) then B→C (t=7000). p1 has both; p2 has only the first
	// (duplicate of p1's). The union dedups the shared event and orders by time.
	ev1 := wireTaintEvent{ID: 1, RefID: 1, Reason: "tag_oid_changed", FromOID: sp(oidA), ToOID: sp(oidB), DetectedAtNS: 5000}
	ev2 := wireTaintEvent{ID: 2, RefID: 1, Reason: "tag_oid_changed", FromOID: sp(oidB), ToOID: sp(oidC), DetectedAtNS: 7000}

	tgFull := tag(1, "v1", oidA, oidC)
	tgFull.Tainted = true
	tgFull.TaintFirstNS = ip(5000)
	p1 := peerView("p1", url, []wireTag{tgFull}, []wireTaintEvent{ev2, ev1}) // out of order on purpose

	tgPart := tag(1, "v1", oidA, oidC)
	tgPart.Tainted = true
	tgPart.TaintFirstNS = ip(5000)
	p2 := peerView("p2", url, []wireTag{tgPart}, []wireTaintEvent{ev1}) // duplicate of ev1

	res := mergeQuorum(map[string][]peerRemoteView{url: {p1, p2}}, 2)
	if len(res.remotes) != 1 || len(res.remotes[0].tags) != 1 {
		t.Fatalf("expected 1 tag, got remotes=%d quarantined=%d", len(res.remotes), res.quarantinedTags)
	}
	mt := res.remotes[0].tags[0]
	if len(mt.events) != 2 {
		t.Fatalf("union should yield 2 deduped events, got %d", len(mt.events))
	}
	if mt.events[0].detectedAtNS != 5000 || mt.events[1].detectedAtNS != 7000 {
		t.Errorf("events not ordered by time: %d then %d", mt.events[0].detectedAtNS, mt.events[1].detectedAtNS)
	}
}

// --- N=1 fast path ----------------------------------------------------------

func TestMerge_N1_AdoptsSinglePeer(t *testing.T) {
	const url = "https://example.com/owner/repo"
	views := []peerRemoteView{peerView("p1", url, []wireTag{tag(1, "v1", oidA, oidA)}, nil)}
	res := mergeQuorum(map[string][]peerRemoteView{url: views}, 1)
	if len(res.remotes) != 1 || len(res.remotes[0].tags) != 1 {
		t.Fatalf("N=1 must adopt the single peer's tag, got remotes=%d", len(res.remotes))
	}
	if res.remotes[0].tags[0].firstOID.Hex() != oidA {
		t.Errorf("first_oid = %s, want %s", res.remotes[0].tags[0].firstOID.Hex(), oidA)
	}
}

// --- algo inference (40-hex sha1, 64-hex sha256) ----------------------------

func TestMerge_AlgoInference(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		algo model.HashAlgo
	}{
		{"sha1", oidA, model.SHA1},
		{"sha256", oid64, model.SHA256},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const url = "https://example.com/owner/repo"
			views := []peerRemoteView{peerView("p1", url, []wireTag{tag(1, "v1", c.hex, c.hex)}, nil)}
			res := mergeQuorum(map[string][]peerRemoteView{url: views}, 1)
			if len(res.remotes) != 1 || len(res.remotes[0].tags) != 1 {
				t.Fatalf("expected 1 tag")
			}
			if got := res.remotes[0].tags[0].firstOID.Algo; got != c.algo {
				t.Errorf("inferred algo = %q, want %q", got, c.algo)
			}
		})
	}
}

// --- continuity validation (C4) ---------------------------------------------

func TestMerge_DiscontinuousSequence_Quarantined(t *testing.T) {
	const url = "https://example.com/owner/repo"
	// first_oid=A but the first event chains from B (not A) → discontinuous → quarantine.
	tg := tag(1, "v1", oidA, oidC)
	tg.Tainted = true
	tg.TaintFirstNS = ip(5000)
	gapEv := wireTaintEvent{ID: 1, RefID: 1, Reason: "tag_oid_changed", FromOID: sp(oidB), ToOID: sp(oidC), DetectedAtNS: 5000}
	v := peerView("p1", url, []wireTag{tg}, []wireTaintEvent{gapEv})
	res := mergeQuorum(map[string][]peerRemoteView{url: {v}}, 1)
	if len(res.remotes) != 1 {
		t.Fatalf("remote should be adopted")
	}
	if len(res.remotes[0].tags) != 0 {
		t.Errorf("discontinuous tag must be quarantined, got %d adopted", len(res.remotes[0].tags))
	}
	if res.quarantinedTags != 1 {
		t.Errorf("quarantinedTags = %d, want 1", res.quarantinedTags)
	}
}

func TestMerge_Deletion_MapsToTagDeleted(t *testing.T) {
	const url = "https://example.com/owner/repo"
	// v1: A then deleted (to_oid empty). The merged event must be tag_deleted.
	tg := tag(1, "v1", oidA, oidA)
	tg.Tainted = true
	tg.Deleted = true
	tg.TaintFirstNS = ip(6000)
	delEv := wireTaintEvent{ID: 1, RefID: 1, Reason: "tag_deleted_recreated", FromOID: sp(oidA), ToOID: nil, DetectedAtNS: 6000}
	v := peerView("p1", url, []wireTag{tg}, []wireTaintEvent{delEv})
	res := mergeQuorum(map[string][]peerRemoteView{url: {v}}, 1)
	if len(res.remotes) != 1 || len(res.remotes[0].tags) != 1 {
		t.Fatalf("deletion sequence should be coherent + adopted, got quarantined=%d", res.quarantinedTags)
	}
	mt := res.remotes[0].tags[0]
	if len(mt.events) != 1 || mt.events[0].eventType != model.EventTagDeleted {
		t.Errorf("deletion must map to tag_deleted, got %+v", mt.events)
	}
	if mt.events[0].taintReason == nil || *mt.events[0].taintReason != model.TaintTagDeletedRecreated {
		t.Errorf("deletion taint reason = %v, want tag_deleted_recreated", mt.events[0].taintReason)
	}
}

func TestMerge_DeleteThenRecreate_EventTypes(t *testing.T) {
	const url = "https://example.com/owner/repo"
	// v1: A, deleted, then recreated at C. Events: tag_deleted (A→empty),
	// tag_recreated (empty→C). Must be coherent.
	tg := tag(1, "v1", oidA, oidC)
	tg.Tainted = true
	tg.TaintFirstNS = ip(6000)
	delEv := wireTaintEvent{ID: 1, RefID: 1, Reason: "tag_deleted_recreated", FromOID: sp(oidA), ToOID: nil, DetectedAtNS: 6000}
	recEv := wireTaintEvent{ID: 2, RefID: 1, Reason: "tag_deleted_recreated", FromOID: nil, ToOID: sp(oidC), DetectedAtNS: 7000}
	v := peerView("p1", url, []wireTag{tg}, []wireTaintEvent{delEv, recEv})
	res := mergeQuorum(map[string][]peerRemoteView{url: {v}}, 1)
	if len(res.remotes) != 1 || len(res.remotes[0].tags) != 1 {
		t.Fatalf("delete-then-recreate should be coherent, got quarantined=%d logs=%+v", res.quarantinedTags, res.quarantineLogs)
	}
	evs := res.remotes[0].tags[0].events
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d", len(evs))
	}
	if evs[0].eventType != model.EventTagDeleted {
		t.Errorf("event 0 = %s, want tag_deleted", evs[0].eventType)
	}
	if evs[1].eventType != model.EventTagRecreated {
		t.Errorf("event 1 = %s, want tag_recreated", evs[1].eventType)
	}
}

// --- annotated-tag fidelity (C1) --------------------------------------------

func TestMerge_AnnotatedClean_GenesisPeeledSet(t *testing.T) {
	const url = "https://example.com/owner/repo"
	// An annotated tag that NEVER changed: current_oid is the tag object, peeled is
	// the commit. Genesis peeled should be set (best-effort is exact here).
	tg := wireTag{
		ID: 1, RemoteID: 1, TagName: "v1",
		FirstOID: sp(oidA), CurrentOID: sp(oidA), CurrentPeeledOID: sp(oidB),
		IsAnnotated: bp(true), FirstSeenNS: 1000, LastSeenNS: 2000,
	}
	res := mergeQuorum(map[string][]peerRemoteView{url: {peerView("p1", url, []wireTag{tg}, nil)}}, 1)
	mt := res.remotes[0].tags[0]
	if !mt.isAnnotated {
		t.Error("is_annotated should be true")
	}
	if mt.genesisPeeledOID.Hex() != oidB {
		t.Errorf("clean annotated genesis peeled = %s, want %s", mt.genesisPeeledOID.Hex(), oidB)
	}
	if mt.currentPeeledOID.Hex() != oidB {
		t.Errorf("current peeled = %s, want %s", mt.currentPeeledOID.Hex(), oidB)
	}
}

func TestMerge_AnnotatedChanged_GenesisPeeledBestEffortEmpty(t *testing.T) {
	const url = "https://example.com/owner/repo"
	// An annotated tag WITH a taint history: genesis peeled is unrecoverable
	// (best-effort empty), but the CURRENT peeled oid is preserved.
	tg := wireTag{
		ID: 1, RemoteID: 1, TagName: "v1",
		FirstOID: sp(oidA), CurrentOID: sp(oidC), CurrentPeeledOID: sp(oidB),
		IsAnnotated: bp(true), FirstSeenNS: 1000, LastSeenNS: 2000,
		Tainted: true, TaintFirstNS: ip(5000),
	}
	ev := wireTaintEvent{ID: 1, RefID: 1, Reason: "tag_oid_changed", FromOID: sp(oidA), ToOID: sp(oidC), DetectedAtNS: 5000}
	res := mergeQuorum(map[string][]peerRemoteView{url: {peerView("p1", url, []wireTag{tg}, []wireTaintEvent{ev})}}, 1)
	if len(res.remotes[0].tags) != 1 {
		t.Fatalf("expected 1 tag, quarantined=%d", res.quarantinedTags)
	}
	mt := res.remotes[0].tags[0]
	if !mt.genesisPeeledOID.IsZero() {
		t.Errorf("changed annotated genesis peeled must be best-effort EMPTY, got %s", mt.genesisPeeledOID.Hex())
	}
	if mt.currentPeeledOID.Hex() != oidB {
		t.Errorf("current peeled must be preserved = %s, want %s", mt.currentPeeledOID.Hex(), oidB)
	}
}

// --- allowlist (unit on the matcher) ----------------------------------------

func TestMatchAllowlist(t *testing.T) {
	cases := []struct {
		allow []string
		url   string
		want  bool
	}{
		{nil, "https://x/y", true}, // empty = all
		{[]string{"https://github.com/org/*"}, "https://github.com/org/a", true},
		{[]string{"https://github.com/org/*"}, "https://github.com/other/a", false},
		{[]string{"*repo"}, "https://x/repo", true},
		{[]string{"https://exact/url"}, "https://exact/url", true},
		{[]string{"https://exact/url"}, "https://exact/url2", false},
	}
	for _, c := range cases {
		if got := matchAllowlist(c.allow, c.url); got != c.want {
			t.Errorf("matchAllowlist(%v, %q) = %v, want %v", c.allow, c.url, got, c.want)
		}
	}
}
