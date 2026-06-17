// Package seed implements seed-on-bootstrap (peer seeding): when a fresh server
// starts with GT_SEED_SERVERS set and an empty remotes table, it bootstraps its
// baseline from one or more peer git-tainted servers — adopting their remotes,
// current tag projections, and taint history under a configurable quorum — then
// rebuilds its own local hash-chain from the imported facts. It reuses the peers'
// existing open read endpoints (no new endpoint) and writes the whole result in
// ONE atomic transaction (all-or-nothing). See
// docs/superpowers/specs/2026-06-17-git-tainted-seed-bootstrap-design.md.
package seed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mivanov93/git-tainted/internal/config"
	"github.com/mivanov93/git-tainted/internal/model"
)

// Seeder bootstraps an empty store from peer servers (spec §4.1). It holds no
// global state and is fully injectable for tests: an *http.Client, the target
// model.Store, the resolved config, a model.Clock, and a logger.
type Seeder struct {
	http  *http.Client
	store model.Store
	cfg   *config.Config
	clk   model.Clock
	log   *slog.Logger
}

// New constructs a Seeder. The http.Client should carry no per-request timeout of
// its own — the Seeder applies GT_SEED_TIMEOUT_NS per request via context.
func New(httpClient *http.Client, store model.Store, cfg *config.Config, clk model.Clock, log *slog.Logger) *Seeder {
	return &Seeder{http: httpClient, store: store, cfg: cfg, clk: clk, log: log}
}

// Run performs the one-shot bootstrap (spec §4.1). It is a NO-OP (returns nil)
// when seeding is disabled or the store already has remotes. Errors are logged,
// not fatal: Run returns nil on a best-effort empty seed so startup proceeds
// (spec §4.2/§5). A non-nil return indicates only a programming/precondition
// error the caller treats as non-fatal too.
func (s *Seeder) Run(ctx context.Context) error {
	if !s.cfg.SeedEnabled() {
		return nil // feature off
	}
	start := time.Now()

	// ---- First-time guard (spec §5): only seed an empty store ----------------
	n, err := s.store.CountAllRemotes(ctx)
	if err != nil {
		s.log.Warn("seed: skipped — could not count remotes", "err", err)
		return nil
	}
	if n != 0 {
		s.log.Info("seed: skipped — store already has remotes", "remotes", n)
		return nil
	}

	peers := s.peerURLs()
	if len(peers) == 0 {
		return nil
	}

	// ---- Bounded-concurrency fetch (spec §4.3) -------------------------------
	byURL, peersUsed := s.fetchAll(ctx, peers)
	if peersUsed == 0 {
		s.log.Warn("seed: no peer reachable — starting empty", "peers_configured", len(peers))
		return nil
	}

	// ---- Quorum merge + continuity validation (in memory, spec §4.4) ---------
	res := mergeQuorum(byURL, s.cfg.SeedQuorum)
	for _, q := range res.quarantineLogs {
		s.log.Warn("seed: tag quarantined", "remote", q.remoteURL, "tag", q.tagName, "reason", q.reason)
	}

	// ---- Fail-loud ceilings (spec §4.5 step 0b / M3) -------------------------
	if len(res.remotes) > s.cfg.SeedMaxRemotes {
		s.log.Warn("seed: aborted — remotes exceed ceiling; starting empty",
			"remotes", len(res.remotes), "max", s.cfg.SeedMaxRemotes)
		return nil
	}
	if res.totalObs > int64(s.cfg.SeedMaxObservations) {
		s.log.Warn("seed: aborted — observations exceed ceiling; starting empty",
			"observations", res.totalObs, "max", s.cfg.SeedMaxObservations)
		return nil
	}

	if len(res.remotes) == 0 {
		s.log.Warn("seed: nothing adopted (all filtered/quarantined/sub-quorum) — starting empty",
			"peers_used", peersUsed, "tags_quarantined", res.quarantinedTags)
		return nil
	}

	// ---- Single atomic write (spec §4.5) -------------------------------------
	adoptedRemotes, adoptedTags, err := s.write(ctx, res)
	if err != nil {
		// Rollback already happened (WithTx). The table stays empty → next boot
		// re-seeds cleanly. Best-effort: log + start empty, never abort startup.
		s.log.Warn("seed: write failed, rolled back — starting empty", "err", err)
		return nil
	}

	s.log.Info("seed: bootstrap complete",
		"remotes_adopted", adoptedRemotes,
		"tags_adopted", adoptedTags,
		"tags_quarantined", res.quarantinedTags,
		"peers_used", peersUsed,
		"peers_configured", len(peers),
		"duration", time.Since(start).String(),
	)
	return nil
}

// peerURLs returns the de-duplicated, ordered list of configured peer base URLs.
func (s *Seeder) peerURLs() []string {
	raw := strings.FieldsFunc(s.cfg.SeedServers, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, u := range raw {
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// ---- fetch (spec §4.3) -----------------------------------------------------

// fetchAll fetches every reachable peer's remotes/tags/taint-events under a single
// shared semaphore (size GT_SEED_CONCURRENCY) across all peers, and groups the
// results by normalized remote URL for the merge. It returns the grouped views and
// the count of peers that contributed at least their remote list (a peer that
// errored anywhere drops out of the tally for the remotes it could not fully
// fetch). Allowlist filtering (GT_SEED_REMOTES) is applied here so quarantine and
// quorum operate over the filtered set only.
func (s *Seeder) fetchAll(ctx context.Context, peers []string) (map[string][]peerRemoteView, int) {
	allow := parseAllowlist(s.cfg.SeedRemotes)
	sem := make(chan struct{}, s.cfg.SeedConcurrency)

	var (
		mu        sync.Mutex
		byURL     = map[string][]peerRemoteView{}
		peersUsed int
		wg        sync.WaitGroup
	)

	for _, peerURL := range peers {
		peerURL := peerURL
		wg.Add(1)
		go func() {
			defer wg.Done()
			client, err := newPeerClient(s.http, peerURL, s.cfg.SeedInsecure)
			if err != nil {
				s.log.Warn("seed: peer rejected", "peer", peerURL, "err", err)
				return
			}
			views, ok := s.fetchPeer(ctx, client, peerURL, allow, sem)
			if !ok {
				return
			}
			mu.Lock()
			peersUsed++
			for i := range views {
				u := views[i].remote.NormalizedURL
				byURL[u] = append(byURL[u], views[i])
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return byURL, peersUsed
}

// fetchPeer fetches one peer's remote list (after the allowlist filter) and, for
// each surviving remote, its tags + taint events — every request bounded by the
// shared semaphore + the per-request deadline. The per-remote tag/taint fetches
// run concurrently (still under the global semaphore). If the peer's remote list
// fails, the peer is dropped (ok=false). If a single remote's tags/taint-events
// fail, that remote is dropped from this peer's contribution but the peer still
// counts for the rest.
func (s *Seeder) fetchPeer(ctx context.Context, client *peerClient, peerURL string, allow []string, sem chan struct{}) ([]peerRemoteView, bool) {
	remotes, err := withSlot(ctx, sem, s.cfg.SeedTimeout, func(rctx context.Context) ([]wireRemote, error) {
		return client.listRemotes(rctx, s.cfg.SeedMaxPages)
	})
	if err != nil {
		s.log.Warn("seed: peer remote list failed — dropping peer", "peer", peerURL, "err", err)
		return nil, false
	}

	// Apply the allowlist filter on the normalized URL.
	filtered := remotes[:0]
	for _, r := range remotes {
		if matchAllowlist(allow, r.NormalizedURL) {
			filtered = append(filtered, r)
		}
	}

	var (
		mu    sync.Mutex
		views []peerRemoteView
		wg    sync.WaitGroup
	)
	for i := range filtered {
		r := filtered[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			tags, terr := withSlot(ctx, sem, s.cfg.SeedTimeout, func(rctx context.Context) ([]wireTag, error) {
				return client.listTags(rctx, r.ID, s.cfg.SeedMaxPages)
			})
			if terr != nil {
				s.log.Warn("seed: peer tags failed — dropping remote from this peer",
					"peer", peerURL, "remote", r.NormalizedURL, "err", terr)
				return
			}
			events, eerr := withSlot(ctx, sem, s.cfg.SeedTimeout, func(rctx context.Context) ([]wireTaintEvent, error) {
				return client.listTaintEvents(rctx, r.ID, s.cfg.SeedMaxPages)
			})
			if eerr != nil {
				s.log.Warn("seed: peer taint-events failed — dropping remote from this peer",
					"peer", peerURL, "remote", r.NormalizedURL, "err", eerr)
				return
			}
			mu.Lock()
			views = append(views, peerRemoteView{peer: peerURL, remote: r, tags: tags, taintEvents: events})
			mu.Unlock()
		}()
	}
	wg.Wait()
	return views, true
}

// withSlot runs fn holding one semaphore slot, under a fresh context bounded by
// the per-request timeout. The slot caps the global fan-out (spec §4.3).
func withSlot[T any](ctx context.Context, sem chan struct{}, timeout time.Duration, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return zero, ctx.Err()
	}
	defer func() { <-sem }()

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return fn(rctx)
}

// ---- allowlist -------------------------------------------------------------

// parseAllowlist splits the GT_SEED_REMOTES comma-separated glob list. Empty ⇒ all.
func parseAllowlist(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// matchAllowlist reports whether url passes the allowlist (empty allow ⇒ all).
func matchAllowlist(allow []string, url string) bool {
	if len(allow) == 0 {
		return true
	}
	for _, pat := range allow {
		if matchGlob(pat, url) {
			return true
		}
	}
	return false
}

// matchGlob implements simple glob matching (* = any run of chars), mirroring the
// API handler's matchGlob so the allowlist behaves like the tags filter.
func matchGlob(pattern, name string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return name == pattern
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]
	for _, p := range parts[1 : len(parts)-1] {
		idx := strings.Index(name, p)
		if idx < 0 {
			return false
		}
		name = name[idx+len(p):]
	}
	return strings.HasSuffix(name, parts[len(parts)-1])
}

// ---- atomic write (spec §4.5) ----------------------------------------------

// ErrSeedGuard is returned (inside the txn) when a remote already exists at write
// time — the TOCTOU backstop (spec §4.5 step 0 / M2). It aborts the seed.
var ErrSeedGuard = errors.New("seed: remotes table is non-empty at write time (aborting)")

// write performs the entire seed in ONE store.WithTx (all-or-nothing, spec §4.5).
// It re-checks the zero-rows guard inside the txn (M2), re-checks the ceilings
// (M3), then per adopted remote creates the remote and rebuilds its chain (genesis
// + per-event observations + taint events), reusing the existing Tx append/advance
// methods + chain.go. Returns the adopted remote/tag counts.
func (s *Seeder) write(ctx context.Context, res mergeResult) (remotesAdopted, tagsAdopted int, err error) {
	now := s.clk.NowNS()
	txErr := s.store.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
		// In-txn guard (M2): re-check zero remotes on the TRANSACTION's connection
		// (Tx.CountAllRemotes), not the Store's — calling the Store-level count here
		// would deadlock a single-connection SQLite pool (the txn already holds the
		// one connection). This closes the §2 "When" TOCTOU window.
		count, cerr := tx.CountAllRemotes(ctx)
		if cerr != nil {
			return fmt.Errorf("in-txn remote count: %w", cerr)
		}
		if count != 0 {
			return ErrSeedGuard
		}

		// Ceiling re-check (M3) — never hold the writer for an unbounded seed.
		if len(res.remotes) > s.cfg.SeedMaxRemotes {
			return fmt.Errorf("seed: %d remotes over ceiling %d", len(res.remotes), s.cfg.SeedMaxRemotes)
		}
		if res.totalObs > int64(s.cfg.SeedMaxObservations) {
			return fmt.Errorf("seed: %d observations over ceiling %d", res.totalObs, s.cfg.SeedMaxObservations)
		}

		for i := range res.remotes {
			mr := &res.remotes[i]
			n, werr := s.writeRemote(ctx, tx, mr, now)
			if werr != nil {
				return fmt.Errorf("write remote %s: %w", mr.normalizedURL, werr)
			}
			remotesAdopted++
			tagsAdopted += n
		}
		return nil
	})
	if txErr != nil {
		return 0, 0, txErr
	}
	return remotesAdopted, tagsAdopted, nil
}

// writeRemote creates one remote and rebuilds its per-tag chains in the txn
// (spec §4.5 steps 1–2). Returns the number of tags written. The ordering matches
// the live path (internal/sync/remote.go): upsert the ref FIRST (to get ref.ID +
// establish first_oid/first_seen_ns/is_annotated), THEN append the genesis +
// per-taint observations with that ref.ID, THEN a final upsert for current_*.
func (s *Seeder) writeRemote(ctx context.Context, tx model.Tx, mr *mergedRemote, now int64) (int, error) {
	remote := &model.Remote{
		URL:                 mr.url,
		NormalizedURL:       mr.normalizedURL,
		Transport:           mr.transport,
		SyncInterval:        s.cfg.SyncDefaultInterval, // cadence is LOCAL (spec §2)
		StalenessBudget:     s.cfg.StalenessBudget,
		TaintAnyTagDeletion: mr.taintAnyTagDeletion,
		Status:              model.RemoteActive,
		ChainHeadHash:       make([]byte, 32), // genesis: 32 zero bytes
		ChainLen:            0,
		CreatedAtNS:         now,
		UpdatedAtNS:         now,
	}
	remoteID, err := tx.CreateRemote(ctx, remote)
	if err != nil {
		return 0, fmt.Errorf("create remote: %w", err)
	}

	// One synthetic sync row anchors the seeded observations' sync_id FK (the live
	// path always WriteSync before AppendObservation). trigger=register marks it as
	// the bootstrap import.
	syncID, err := tx.WriteSync(ctx, &model.Sync{
		RemoteID:        remoteID,
		Trigger:         model.TriggerRegister,
		StartedNS:       now,
		FinishedNS:      now,
		Status:          model.SyncOk,
		TagsSeen:        len(mr.tags),
		ChainHeadBefore: make([]byte, 32),
	})
	if err != nil {
		return 0, fmt.Errorf("write seed sync: %w", err)
	}

	for i := range mr.tags {
		if err := s.writeTag(ctx, tx, remoteID, syncID, &mr.tags[i]); err != nil {
			return 0, fmt.Errorf("tag %s: %w", mr.tags[i].name, err)
		}
	}
	return len(mr.tags), nil
}

// writeTag rebuilds one tag's chain (spec §4.5 step 2 a–d). It upserts the ref
// FIRST to get ref.ID + establish the immutable first_* fields, appends the
// genesis observation, then one observation (+ taint_events row) per merged event,
// then a final upsert carrying current_*/tainted/taint_first_ns/observation_count.
func (s *Seeder) writeTag(ctx context.Context, tx model.Tx, remoteID model.RemoteID, syncID model.SyncID, mt *mergedTag) error {
	// (a) Upsert the ref FIRST — this DO-UPDATE-free first insert must carry
	// first_oid / first_seen_ns / is_annotated correctly (UpsertRef's DO UPDATE does
	// not touch first_oid/first_seen_ns).
	ref := &model.Ref{
		RemoteID:         remoteID,
		TagName:          mt.name,
		CurrentOID:       mt.firstOID, // interim until the final upsert (d)
		CurrentPeeledOID: mt.genesisPeeledOID,
		IsAnnotatedTag:   mt.isAnnotated,
		FirstOID:         mt.firstOID,
		FirstSeenNS:      mt.firstSeenNS,
		LastSeenNS:       mt.firstSeenNS,
		LastChangedNS:    mt.firstSeenNS,
		ObservationCount: 0,
	}
	if err := tx.UpsertRefProjection(ctx, ref); err != nil {
		return fmt.Errorf("upsert ref (initial): %w", err)
	}

	// (b) Genesis observation — event_type=tag_created, new_oid=first_oid,
	// new_peeled_oid=genesisPeeledOID (set only when the tag never changed, C1),
	// observed_at_ns=first_seen_ns, canonical_meta="" (the live path never sets it).
	genObs := &model.Observation{
		RemoteID:     remoteID,
		RefID:        ref.ID,
		SyncID:       syncID,
		EventType:    model.EventTagCreated,
		NewOID:       mt.firstOID,
		NewPeeledOID: mt.genesisPeeledOID,
		ObservedAtNS: mt.firstSeenNS,
	}
	if _, err := tx.AppendObservation(ctx, genObs); err != nil {
		return fmt.Errorf("append genesis observation: %w", err)
	}
	obsCount := int64(1)

	// (c) One observation per merged taint event, in continuous order, with the
	// correct event type + a matching taint_events row.
	for i := range mt.events {
		ev := &mt.events[i]
		obs := &model.Observation{
			RemoteID:     remoteID,
			RefID:        ref.ID,
			SyncID:       syncID,
			EventType:    ev.eventType,
			PrevOID:      ev.fromOID,
			NewOID:       ev.toOID,
			ObservedAtNS: ev.detectedAtNS,
		}
		if _, err := tx.AppendObservation(ctx, obs); err != nil {
			return fmt.Errorf("append event observation %d: %w", i, err)
		}
		obsCount++
		if ev.taintReason != nil {
			te := &model.TaintEvent{
				RemoteID:      remoteID,
				RefID:         ref.ID,
				Reason:        *ev.taintReason,
				ObservationID: &obs.ID,
				FromOID:       ev.fromOID,
				ToOID:         ev.toOID,
				DetectedAtNS:  ev.detectedAtNS,
			}
			if _, err := tx.AppendTaintEvent(ctx, te); err != nil {
				return fmt.Errorf("append taint event %d: %w", i, err)
			}
		}
	}

	// (d) Final upsert of the ref projection: current_*/tainted/taint_first_ns/
	// observation_count = appended-observation count.
	ref.CurrentOID = orFirst(mt.currentOID, mt.firstOID)
	ref.CurrentPeeledOID = mt.currentPeeledOID
	ref.LastSeenNS = orInt(mt.lastSeenNS, mt.firstSeenNS)
	ref.Deleted = mt.deleted
	ref.Tainted = mt.tainted
	ref.TaintFirstNS = mt.taintFirstNS
	ref.ObservationCount = obsCount
	if len(mt.events) > 0 {
		ref.LastChangedNS = mt.events[len(mt.events)-1].detectedAtNS
	}
	if err := tx.UpsertRefProjection(ctx, ref); err != nil {
		return fmt.Errorf("upsert ref (final): %w", err)
	}
	return nil
}

// orFirst returns oid if set, else fallback.
func orFirst(oid, fallback model.OID) model.OID {
	if oid.IsZero() {
		return fallback
	}
	return oid
}

// orInt returns v if non-zero, else fallback.
func orInt(v, fallback int64) int64 {
	if v == 0 {
		return fallback
	}
	return v
}
