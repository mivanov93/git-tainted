package seed

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mivanov93/git-tainted/internal/model"
)

// ---- merge inputs ----------------------------------------------------------

// peerRemoteView is one peer's complete view of a single remote (its remote row
// plus that remote's tags and taint events as the peer reports them). The Seeder
// builds one per (peer, remote) and groups them by normalized URL for the merge.
type peerRemoteView struct {
	peer        string // peer base URL (for quarantine logging)
	remote      wireRemote
	tags        []wireTag
	taintEvents []wireTaintEvent
}

// ---- merge outputs ---------------------------------------------------------

// mergedRemote is an adopted remote with its validated, continuity-checked tags,
// ready for the single atomic write (spec §4.5). It carries no peer row-hashes;
// the server rebuilds its own chain.
type mergedRemote struct {
	url                 string
	normalizedURL       string
	transport           model.Transport
	taintAnyTagDeletion bool
	tags                []mergedTag
}

// mergedTag is one adopted tag's rebuilt history: a genesis baseline plus an
// ordered, continuity-validated event sequence, the current projection, and the
// quorum-gated taint verdict.
type mergedTag struct {
	name        string
	firstOID    model.OID
	isAnnotated bool
	// genesisPeeledOID is best-effort: set from current_peeled_oid ONLY when the
	// tag never changed (no taint events), else zero (the historical peeled oid is
	// unrecoverable — spec §2 fidelity gap, C1).
	genesisPeeledOID model.OID
	firstSeenNS      int64
	// events are the post-genesis observations in continuous order. Empty for a
	// never-changed tag.
	events []mergedEvent
	// current projection (interim — the first live sync overwrites it).
	currentOID       model.OID
	currentPeeledOID model.OID
	lastSeenNS       int64
	deleted          bool
	// taint verdict (quorum-gated, M1).
	tainted      bool
	taintFirstNS *int64
}

// mergedEvent is one post-genesis observation to append, with the correct
// observation event type and (for taints) the matching taint reason.
type mergedEvent struct {
	eventType    model.ObservationEventType
	taintReason  *model.TaintReason // non-nil ⇒ append a taint_events row too
	fromOID      model.OID          // prev oid (zero only for a recreation from deletion)
	toOID        model.OID          // new oid (zero ⇒ deletion)
	detectedAtNS int64
}

// mergeResult is the whole in-memory merge outcome.
type mergeResult struct {
	remotes         []mergedRemote
	totalObs        int64 // genesis + per-event observations across all remotes
	quarantinedTags int
	quarantineLogs  []quarantineLog
}

// quarantineLog records a per-tag skip with the disagreement, for actionable
// Warn logging (spec §5).
type quarantineLog struct {
	remoteURL string
	tagName   string
	reason    string
}

// ---- merge -----------------------------------------------------------------

// mergeQuorum performs the in-memory quorum merge over every peer-remote view,
// keyed by normalized remote URL then tag name (spec §4.4). quorum N is the
// minimum number of distinct peers that must agree on a fact. A tag whose facts
// don't reach N agreement — or whose event sequence isn't continuous — is
// quarantined (skipped + logged), never written. Remotes are returned sorted by
// normalized URL and tags by name for deterministic output.
func mergeQuorum(byURL map[string][]peerRemoteView, quorum int) mergeResult {
	var res mergeResult

	urls := make([]string, 0, len(byURL))
	for u := range byURL {
		urls = append(urls, u)
	}
	sort.Strings(urls)

	for _, normURL := range urls {
		views := byURL[normURL]
		// Remote adoption: require >= N distinct peers reporting this remote. Each
		// view comes from a distinct peer (the Seeder dedups peers), so len is the
		// distinct-peer count.
		if len(views) < quorum {
			continue
		}

		mr := mergedRemote{
			normalizedURL:       normURL,
			url:                 adoptRemoteURL(views),
			transport:           adoptTransport(views),
			taintAnyTagDeletion: adoptTaintPolicy(views),
		}

		// Collect, per tag name, every peer's view of that tag.
		tagViews := map[string][]taggedView{}
		for _, v := range views {
			eventsByRef := map[int64][]wireTaintEvent{}
			for _, e := range v.taintEvents {
				eventsByRef[e.RefID] = append(eventsByRef[e.RefID], e)
			}
			for _, t := range v.tags {
				tagViews[t.TagName] = append(tagViews[t.TagName], taggedView{
					peer:   v.peer,
					tag:    t,
					events: eventsByRef[t.ID],
				})
			}
		}

		names := make([]string, 0, len(tagViews))
		for n := range tagViews {
			names = append(names, n)
		}
		sort.Strings(names)

		for _, name := range names {
			mt, qlog, ok := mergeTag(normURL, name, tagViews[name], quorum)
			if !ok {
				res.quarantinedTags++
				res.quarantineLogs = append(res.quarantineLogs, qlog)
				continue
			}
			mr.tags = append(mr.tags, mt)
			res.totalObs++                        // genesis observation
			res.totalObs += int64(len(mt.events)) // per-event observations
		}

		res.remotes = append(res.remotes, mr)
	}
	return res
}

// taggedView is one peer's view of a single tag plus that peer's taint events for
// the tag's ref.
type taggedView struct {
	peer   string
	tag    wireTag
	events []wireTaintEvent
}

// mergeTag merges one tag across peers under quorum and validates continuity. It
// returns the merged tag, or (a quarantine log, false) if no first_oid reaches N
// agreement or the resulting sequence is not continuous.
func mergeTag(remoteURL, name string, views []taggedView, quorum int) (mergedTag, quarantineLog, bool) {
	// ---- first_oid (trust baseline): adopt the value with >= N agreement -----
	firstHexCount := map[string]int{}
	for _, v := range views {
		if v.tag.FirstOID != nil && *v.tag.FirstOID != "" {
			firstHexCount[*v.tag.FirstOID]++
		}
	}
	firstHex, ok := pickQuorumValue(firstHexCount, quorum)
	if !ok {
		return mergedTag{}, quarantineLog{
			remoteURL: remoteURL, tagName: name,
			reason: "no first_oid reached quorum: " + describeCounts(firstHexCount),
		}, false
	}
	firstOID, err := parseHexOID(firstHex)
	if err != nil {
		return mergedTag{}, quarantineLog{
			remoteURL: remoteURL, tagName: name,
			reason: fmt.Sprintf("first_oid %q invalid: %v", firstHex, err),
		}, false
	}

	// The peers that agree on first_oid form the cohort whose other facts we adopt.
	cohort := make([]taggedView, 0, len(views))
	for _, v := range views {
		if v.tag.FirstOID != nil && *v.tag.FirstOID == firstHex {
			cohort = append(cohort, v)
		}
	}

	mt := mergedTag{
		name:        name,
		firstOID:    firstOID,
		isAnnotated: adoptIsAnnotated(cohort),
		firstSeenNS: minFirstSeenNS(cohort),
	}

	// ---- current projection from the freshest agreeing peer (interim) --------
	fresh := freshestView(cohort)
	if fresh.tag.CurrentOID != nil && *fresh.tag.CurrentOID != "" {
		if oid, err := parseHexOID(*fresh.tag.CurrentOID); err == nil {
			mt.currentOID = oid
		}
	}
	if fresh.tag.CurrentPeeledOID != nil && *fresh.tag.CurrentPeeledOID != "" {
		if oid, err := parseHexOID(*fresh.tag.CurrentPeeledOID); err == nil {
			mt.currentPeeledOID = oid
		}
	}
	mt.lastSeenNS = fresh.tag.LastSeenNS
	mt.deleted = fresh.tag.Deleted

	// ---- taint verdict (quorum-gated, M1) ------------------------------------
	taintedCount := 0
	for _, v := range views {
		if v.tag.Tainted {
			taintedCount++
		}
	}
	adoptTainted := taintedCount >= quorum

	// ---- build the event sequence (union of taint events when adopted) -------
	var events []mergedEvent
	if adoptTainted {
		// Union only the AGREEING (tainted-reporting) peers' events (spec §4.4): a
		// peer that reports the tag NOT tainted is not part of the taint quorum and
		// must not inject taint history — defense against an inconsistent peer
		// padding a genuinely-tainted tag's history with extra (coherent) events.
		taintedViews := make([]taggedView, 0, len(views))
		for _, v := range views {
			if v.tag.Tainted {
				taintedViews = append(taintedViews, v)
			}
		}
		union := unionTaintEvents(taintedViews)
		var earliest *int64
		for i := range union {
			ev, perr := taintEventToMerged(union[i])
			if perr != nil {
				return mergedTag{}, quarantineLog{
					remoteURL: remoteURL, tagName: name,
					reason: fmt.Sprintf("taint event invalid: %v", perr),
				}, false
			}
			events = append(events, ev)
			if earliest == nil || union[i].DetectedAtNS < *earliest {
				v := union[i].DetectedAtNS
				earliest = &v
			}
		}
		mt.tainted = true
		// taint_first_ns: earliest detected_at among agreeing peers; fall back to
		// the agreeing peers' reported taint_first_ns if no events carried a time.
		if earliest == nil {
			earliest = earliestTaintFirstNS(views)
		}
		mt.taintFirstNS = earliest
	}

	// ---- genesis peeled oid (C1): only when the tag never changed ------------
	if len(events) == 0 && !mt.currentPeeledOID.IsZero() {
		mt.genesisPeeledOID = mt.currentPeeledOID
	}

	// ---- continuity validation (C4) ------------------------------------------
	if err := validateContinuity(firstOID, events); err != nil {
		return mergedTag{}, quarantineLog{
			remoteURL: remoteURL, tagName: name,
			reason: "discontinuous event sequence: " + err.Error(),
		}, false
	}

	mt.events = events
	return mt, quarantineLog{}, true
}

// ---- continuity (C4) -------------------------------------------------------

// validateContinuity checks that the rebuilt chain is coherent (spec §2/§4.4):
//   - the first event's from_oid equals first_oid;
//   - each event's from_oid equals the previous event's to_oid;
//   - deletions (to_oid empty) carry tag_deleted/tag_recreated event types, never
//     tag_oid_changed; a recreation's from_oid may be empty (from a prior deletion).
func validateContinuity(firstOID model.OID, events []mergedEvent) error {
	if len(events) == 0 {
		return nil
	}
	prevTo := firstOID
	prevWasDeletion := false
	for i, e := range events {
		// Event-type ↔ deletion consistency.
		switch e.eventType {
		case model.EventTagOIDChanged:
			if e.toOID.IsZero() {
				return fmt.Errorf("event %d is tag_oid_changed but has no to_oid (a deletion)", i)
			}
		case model.EventTagDeleted:
			if !e.toOID.IsZero() {
				return fmt.Errorf("event %d is tag_deleted but has a to_oid", i)
			}
		case model.EventTagRecreated:
			if e.toOID.IsZero() {
				return fmt.Errorf("event %d is tag_recreated but has no to_oid", i)
			}
		case model.EventTagCreated:
			return fmt.Errorf("event %d is tag_created (only the genesis may be created)", i)
		default:
			return fmt.Errorf("event %d has unknown event type %q", i, e.eventType)
		}

		// from_oid continuity. A recreation immediately after a deletion legitimately
		// starts from an empty from_oid (the tag did not exist), so allow a zero
		// from_oid there; otherwise from_oid must equal the previous to_oid.
		if e.fromOID.IsZero() {
			if e.eventType != model.EventTagRecreated || !prevWasDeletion {
				return fmt.Errorf("event %d has an empty from_oid but is not a recreation after a deletion", i)
			}
		} else if !oidEqualLoose(e.fromOID, prevTo) {
			return fmt.Errorf("event %d from_oid %s does not chain from previous %s", i, e.fromOID.Hex(), prevTo.Hex())
		}

		prevTo = e.toOID
		prevWasDeletion = e.eventType == model.EventTagDeleted
	}
	return nil
}

// ---- taint event helpers ---------------------------------------------------

// unionTaintEvents unions every peer's taint events for a tag, dedups by
// (from_oid, to_oid, detected_at_ns), and orders by detected_at_ns (ties broken by
// the from/to oids for determinism) — spec §4.4.
func unionTaintEvents(views []taggedView) []wireTaintEvent {
	seen := map[string]struct{}{}
	var out []wireTaintEvent
	for _, v := range views {
		for _, e := range v.events {
			k := strDeref(e.FromOID) + "|" + strDeref(e.ToOID) + "|" + fmt.Sprint(e.DetectedAtNS)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].DetectedAtNS != out[j].DetectedAtNS {
			return out[i].DetectedAtNS < out[j].DetectedAtNS
		}
		if strDeref(out[i].FromOID) != strDeref(out[j].FromOID) {
			return strDeref(out[i].FromOID) < strDeref(out[j].FromOID)
		}
		return strDeref(out[i].ToOID) < strDeref(out[j].ToOID)
	})
	return out
}

// taintEventToMerged maps a wire taint event to a mergedEvent, deriving the
// observation event type from the taint reason and the from/to oid presence
// (C4: deletions → tag_deleted/tag_recreated, not tag_oid_changed).
func taintEventToMerged(e wireTaintEvent) (mergedEvent, error) {
	var fromOID, toOID model.OID
	if e.FromOID != nil && *e.FromOID != "" {
		o, err := parseHexOID(*e.FromOID)
		if err != nil {
			return mergedEvent{}, fmt.Errorf("from_oid %q: %w", *e.FromOID, err)
		}
		fromOID = o
	}
	if e.ToOID != nil && *e.ToOID != "" {
		o, err := parseHexOID(*e.ToOID)
		if err != nil {
			return mergedEvent{}, fmt.Errorf("to_oid %q: %w", *e.ToOID, err)
		}
		toOID = o
	}

	reason := model.TaintReason(e.Reason)
	me := mergedEvent{fromOID: fromOID, toOID: toOID, detectedAtNS: e.DetectedAtNS, taintReason: &reason}

	switch {
	case toOID.IsZero():
		// Deletion.
		me.eventType = model.EventTagDeleted
	case fromOID.IsZero():
		// Reappeared from nothing → recreation.
		me.eventType = model.EventTagRecreated
	case reason == model.TaintTagDeletedRecreated:
		me.eventType = model.EventTagRecreated
	default:
		me.eventType = model.EventTagOIDChanged
	}
	return me, nil
}

// earliestTaintFirstNS returns the earliest non-nil taint_first_ns among the
// tainted-reporting peers, or nil if none reported one.
func earliestTaintFirstNS(views []taggedView) *int64 {
	var earliest *int64
	for _, v := range views {
		if v.tag.Tainted && v.tag.TaintFirstNS != nil {
			if earliest == nil || *v.tag.TaintFirstNS < *earliest {
				val := *v.tag.TaintFirstNS
				earliest = &val
			}
		}
	}
	return earliest
}

// ---- per-fact adoption helpers ---------------------------------------------

// adoptRemoteURL returns the raw URL agreed by the most peers (deterministic tie
// break), so a single peer cannot skew the stored display URL.
func adoptRemoteURL(views []peerRemoteView) string {
	counts := map[string]int{}
	for _, v := range views {
		counts[v.remote.URL]++
	}
	best, _ := pickMostCommon(counts)
	return best
}

func adoptTransport(views []peerRemoteView) model.Transport {
	counts := map[string]int{}
	for _, v := range views {
		counts[v.remote.Transport]++
	}
	best, _ := pickMostCommon(counts)
	t := model.Transport(best)
	if t != model.TransportHTTPS && t != model.TransportSSH {
		t = model.TransportHTTPS // safe default; cadence/transport is non-security here
	}
	return t
}

func adoptTaintPolicy(views []peerRemoteView) bool {
	trueCount, falseCount := 0, 0
	for _, v := range views {
		if v.remote.TaintAnyTagDeletion {
			trueCount++
		} else {
			falseCount++
		}
	}
	// Default-true bias on a tie (the model default is true).
	return trueCount >= falseCount
}

// adoptIsAnnotated returns the majority is_annotated among the cohort (peers that
// agree on first_oid); absent values are treated as false.
func adoptIsAnnotated(cohort []taggedView) bool {
	trueCount, falseCount := 0, 0
	for _, v := range cohort {
		if v.tag.IsAnnotated != nil && *v.tag.IsAnnotated {
			trueCount++
		} else {
			falseCount++
		}
	}
	return trueCount > falseCount
}

// minFirstSeenNS returns the earliest first_seen_ns among the cohort (the oldest
// observation of the baseline is the most faithful genesis time).
func minFirstSeenNS(cohort []taggedView) int64 {
	var min int64
	for i, v := range cohort {
		if i == 0 || v.tag.FirstSeenNS < min {
			min = v.tag.FirstSeenNS
		}
	}
	return min
}

// freshestView returns the cohort view with the highest last_seen_ns (its current
// projection is the most up-to-date).
func freshestView(cohort []taggedView) taggedView {
	best := cohort[0]
	for _, v := range cohort[1:] {
		if v.tag.LastSeenNS > best.tag.LastSeenNS {
			best = v
		}
	}
	return best
}

// ---- small utilities -------------------------------------------------------

// pickQuorumValue returns the value whose count is >= quorum and is the highest;
// false if none reaches quorum. Ties are broken lexicographically for determinism.
func pickQuorumValue(counts map[string]int, quorum int) (string, bool) {
	best := ""
	bestN := 0
	for v, n := range counts {
		if n < quorum {
			continue
		}
		if n > bestN || (n == bestN && v < best) {
			best, bestN = v, n
		}
	}
	return best, bestN >= quorum
}

// pickMostCommon returns the highest-count value (lexicographic tie break).
func pickMostCommon(counts map[string]int) (string, int) {
	best := ""
	bestN := -1
	for v, n := range counts {
		if n > bestN || (n == bestN && v < best) {
			best, bestN = v, n
		}
	}
	return best, bestN
}

// describeCounts renders a value→count map for a quarantine log line.
func describeCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "(no peer reported a first_oid)"
	}
	parts := make([]string, 0, len(counts))
	for v, n := range counts {
		parts = append(parts, fmt.Sprintf("%s×%d", short(v), n))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func short(hex string) string {
	if len(hex) > 12 {
		return hex[:12]
	}
	return hex
}

func strDeref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// parseHexOID parses a peer-supplied hex oid, inferring the algo from hex length
// (40→sha1, 64→sha256) per the §8 prerequisite (the store then re-infers the algo
// from the raw byte width at decode, C2).
func parseHexOID(hexStr string) (model.OID, error) {
	hexStr = strings.TrimSpace(strings.ToLower(hexStr))
	algo := model.AlgoForRawLen(len(hexStr) / 2)
	if algo == "" {
		return model.OID{}, fmt.Errorf("oid %q has an unsupported width (%d hex chars)", hexStr, len(hexStr))
	}
	oid, err := model.ParseOID(hexStr, algo)
	if err != nil {
		return model.OID{}, fmt.Errorf("parse oid: %w", err)
	}
	return oid, nil
}

// oidEqualLoose compares two oids by raw bytes regardless of algo label. Both come
// from the same peer fleet (so the same algo), but the genesis first_oid and an
// event's from_oid are parsed independently; comparing raw bytes avoids a spurious
// algo mismatch if a peer ever mixed widths.
func oidEqualLoose(a, b model.OID) bool {
	if a.Algo == b.Algo {
		return a.Equal(b)
	}
	if len(a.Raw) != len(b.Raw) {
		return false
	}
	for i := range a.Raw {
		if a.Raw[i] != b.Raw[i] {
			return false
		}
	}
	return true
}
