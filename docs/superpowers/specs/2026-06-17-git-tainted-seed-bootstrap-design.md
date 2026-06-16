# git-tainted — Seed-on-bootstrap (peer seeding) — Design Spec

- **Status:** Approved design, not yet implemented
- **Date:** 2026-06-17
- **Author:** Mihail Ivanov
- **Repo:** `~/Projects/git-tainted`
- **Module:** `github.com/mivanov93/git-tainted`
- **Relates to:** [`2026-06-14-git-tainted-design.md`](2026-06-14-git-tainted-design.md) §3 (threat model) and [`2026-06-16-git-tainted-control-plane-design.md`](2026-06-16-git-tainted-control-plane-design.md) (auth: reads are never gated; the verify CLI's query-time quorum).

> **What this adds.** When a **new** server starts for the first time with `GT_SEED_SERVERS` set, it bootstraps itself from one or more **peer git-tainted servers** — adopting their remotes, current tag projections, and taint history — instead of starting blind (trust-on-first-observation from scratch). It reuses the peers' **existing read endpoints** (no new endpoint) and rebuilds its own local hash-chain from the imported facts. A configurable **quorum** turns seeding from a convenience bootstrap (N=1) into a corroboration defense (N>1).

---

## 1. Motivation & threat-model framing

A fresh server has no history: the first oid its own `ls-remote` returns for a tag becomes its truth (the §3 "trust-on-first-observation, per remote" limitation), so it cannot detect a tag that was already tampered *before* it started watching. Operators running a fleet (or replacing/adding a node) want a new server to inherit the fleet's existing baseline rather than re-establish trust from zero.

Seeding **shifts trust-on-first-observation from the new server's own `ls-remote` to the seed peers.** That is strictly better when the peers are older/trusted, and strictly worse if a seed peer is lying. The `GT_SEED_QUORUM` knob lets the operator choose where on that spectrum to sit: N=1 trusts a single peer (convenience); N>1 requires independent corroboration before adopting any fact (a single poisoned peer cannot taint the bootstrap). This mirrors the verify CLI's existing query-time multi-server quorum, applied at bootstrap.

**Honest posture (documented in the README §Honest posture):** a seeded baseline is only as trustworthy as the quorum of peers that produced it; with N=1 you inherit that peer's blind spots and any pre-seed tamper it already trusted. Seeding never weakens detection *going forward* — the rebuilt chain is tamper-evident and the new server's own `ls-remote` syncs continue normally.

## 2. Decisions (locked)

| # | Decision |
|---|---|
| Trust model | **Configurable quorum** `GT_SEED_QUORUM` (default **1**). A remote/tag fact is adopted only if **≥N** seed peers agree. N=1 = convenience bootstrap; N>1 = corroboration. |
| Fidelity / endpoint | **Reuse the peers' existing read endpoints — NO new endpoint.** `listRemotes` + `listTags` (carries `first_oid`, `current_oid`, `tainted`, `taint_first_ns`) + `listTaintEvents` (every taint's `from_oid→to_oid`+time) already expose the full *meaningful* history. The byte-exact observation ledger / `/audit` replay endpoint is **out of scope** (future extension). |
| Scope | **Mirror + allowlist.** Adopt *all* the peers' remotes by default; an optional `GT_SEED_REMOTES` glob restricts to a subset. |
| When | **First time only** — runs iff `GT_SEED_SERVERS` is set **and** the local `remotes` table has **zero rows** (incl. soft-deleted). |
| Atomicity | **All-or-nothing** — the entire seed is written in **one transaction**; a crash mid-seed rolls back to an empty table, so the next boot re-seeds cleanly. No silently-partial state, no completion marker. |
| Failure | **Best-effort** — a total failure (no peer reachable / quorum unmet / write error → rollback) logs a warning and the server **starts empty**, never aborting startup; the next boot retries (the table is still empty). |
| Taint merge | **Conservative / any-bad** — if any agreeing peer reports a tag tainted, it is adopted tainted (taint is sticky; a credible taint is not voted away). |
| Conflict | **Quarantine** — if peers disagree on a tag's `first_oid` and no value reaches N, the tag is **skipped + logged loudly** (a poisoning signal), not guessed. |
| Cadence | Adopt the peer's URL / transport / taint-policy, but use **this** server's default sync interval + staleness budget (cadence is the new operator's call). |
| Auth | Seeding calls only the peers' **open read endpoints** (never gated per the control-plane auth design), so it needs no credentials even against an auth-enabled peer. |

## 3. Configuration (`internal/config`)

All new keys under `GT_SEED_*`; durations are `time.Duration` in code (env keeps the `_NS` ns wire name), per the duration convention.

| Env | Type | Default | Meaning |
|---|---|---|---|
| `GT_SEED_SERVERS` | string (comma/space list) | `""` | Peer base URLs. Empty ⇒ feature off. |
| `GT_SEED_QUORUM` | int | `1` | Min peers that must agree to adopt a remote/tag fact. |
| `GT_SEED_REMOTES` | string (comma list of globs) | `""` (all) | Optional allowlist filter on the adopted remote URLs. |
| `GT_SEED_CONCURRENCY` | int | `8` | Max in-flight peer HTTP requests (the bounded-fan-out knob). |
| `GT_SEED_TIMEOUT_NS` | duration | `30s` | Per-request HTTP deadline. |
| `GT_SEED_INSECURE` | bool | `false` | Allow plaintext `http://` to non-loopback peers (mirrors the CLI guard). |

Validation: `GT_SEED_QUORUM >= 1`; if set, it may not exceed `len(GT_SEED_SERVERS)` (else no fact could ever be adopted — fail fast at startup). `GT_SEED_CONCURRENCY >= 1`.

## 4. Architecture

### 4.1 `internal/seed` package

A self-contained, injectable unit (no globals; testable):

```go
package seed

// Seeder bootstraps an empty store from peer servers. It is constructed with an
// *http.Client (injectable for tests), the target model.Store, the resolved
// config, a model.Clock, and a logger.
type Seeder struct { /* client, store, cfg, clk, log */ }

// Run performs the one-shot bootstrap. It is a NO-OP (returns nil) when seeding
// is disabled or the store already has remotes. Errors are logged, not fatal:
// Run returns nil on a best-effort partial/empty seed so startup proceeds.
func (s *Seeder) Run(ctx context.Context) error
```

A thin **peer client** (in the same package) wraps the read endpoints with pagination + the transport guard, deserializing into local DTOs that mirror the `Remote`/`Tag`/`TaintEvent` wire shapes (it does **not** import `internal/api/oapi` — same lean pattern as the CLIs).

### 4.2 Boot wiring (`cmd/git-taintedd/main.go`)

After the store (and cache decorator) are ready and **before** the scheduler goroutine starts:

```go
if cfg.SeedEnabled() {
    if err := seed.New(httpClient, cached, cfg, clk, log).Run(ctx); err != nil {
        log.Error("seed bootstrap failed", "err", err) // non-fatal
    }
}
// ... then start the scheduler as today
```

Seeding writes through the **same cached `model.Store`** the rest of the server uses (the cache is empty at boot; its invalidation is exercised harmlessly).

### 4.3 Fetch orchestration ("gazillion requests, prudently")

A single `errgroup`/semaphore of size `GT_SEED_CONCURRENCY` shared across **all** peers:
1. Per peer, paginate `GET /v1/remotes`.
2. For each peer-remote (after the `GT_SEED_REMOTES` allowlist filter): paginate `GET /v1/remotes/{id}/tags` and `GET /v1/remotes/{id}/taint-events`.

Every request is bounded by the shared semaphore and the per-request timeout. A peer that errors or times out is logged and **its votes are dropped** from the tally (the others still count). HTTP/2/3 multiplexing + the peer's Otter cache keep the many small reads cheap; the semaphore keeps the fan-out bounded.

### 4.4 Quorum merge

Keyed by **normalized remote URL**, then by **tag name**:
- **Remote adoption:** adopt a remote iff ≥N distinct peers report it (post-allowlist).
- **Per-tag `first_oid` (the trust baseline):** group peers' reported `first_oid`; adopt the value with ≥N agreement. If none reaches N → **quarantine** (skip the tag, `log.Warn` with the disagreeing oids).
- **`tainted`:** any-bad — tainted if **any** agreeing peer reports it tainted; take the earliest `taint_first_ns` among them.
- **Taint events:** union the agreeing peers' taint events for the tag, deduped by `(from_oid,to_oid,detected_at_ns)`, ordered by `detected_at_ns`.

(N=1 collapses these to "take the single peer's values," with no quarantine path.)

### 4.5 Atomic write — local chain rebuild in one transaction

Fetch + quorum-merge run **in memory** (no DB writes; no transaction is held during network I/O). The merged result is then written in a **single `store.WithTx`**, making the whole seed all-or-nothing (§2 Atomicity).

The hash-chain's canonical row embeds the **local** `remote_id` (`store/chain.go`), so peer row-hashes cannot transfer; the server rebuilds its own chain from the merged facts. Inside the one transaction, for each adopted remote:
1. `tx.CreateRemote(...)` assigns the local id. **Seam change:** `CreateRemote` is added to the `model.Tx` interface — implemented by the sqlite/mysql tx types and the cache decorator's `captureTx` (which bumps the set-generation on commit). It is a natural extension of the write-txn seam; the normal API path keeps using the top-level `Store.CreateRemote`.
2. For each adopted tag: append a **genesis observation** (`event_type=created`, `new_oid=first_oid`, `observed_at_ns=first_seen_ns`) from the 32-zero genesis; then one **`tag_oid_changed` observation** per merged taint event (`prev_oid→new_oid`, `observed_at_ns=detected_at_ns`) — each advancing the SHA-256 chain via `chain.go` + `tx.AdvanceChainHead`, with the matching `taint_events` row. Finally upsert the **ref projection**: `first_oid`, `first_seen_ns`, `tainted`, `taint_first_ns`, `observation_count` = appended-observation count, and `current_oid` = the freshest agreeing peer's `current_oid` (an **interim** value the first live sync overwrites within one tick — only `first_oid` is the durable trust baseline).

This reuses `store.WithTx`, `chain.go`, and the existing `Tx` append/advance methods verbatim; the only new persistence primitive is `Tx.CreateRemote`. The transaction is short (in-memory data → DB, no network); its size scales with the fleet — fine at realistic scale, with a batched-commit variant noted in §7 for pathological fleets. `testutil.AssertChainIntact` must hold for every seeded remote.

### 4.6 After seeding

The scheduler starts and the new server's own `ls-remote` produces the live observation for each tag. Because the seeded `first_oid` is now the chain's baseline, a live oid that diverges from it correctly produces a `tag_oid_changed` taint — i.e. the new server immediately detects a tag that moved between the peers' last sight and its own first sight. Already-tainted (sticky) tags stay tainted.

## 5. Error handling & idempotency

- **First-time guard:** `Run` no-ops unless `GT_SEED_SERVERS` is set and the `remotes` table has **zero rows** (counting soft-deleted rows, so a server never re-seeds after its fleet was later emptied).
- **Atomicity — the crash story:** fetch + merge build the full result in memory; the writes then go through **one `store.WithTx`**. A crash / kill / OOM / reboot at *any* point — during fetch, merge, or the write txn — leaves the `remotes` table empty (the txn either never opened or rolled back), so the **next boot re-seeds cleanly** from the peers. There is no silently-partial fleet and no marker to drift out of sync. Restarting *during* seeding is identical: nothing is half-committed.
- **Total failure** (no peer reachable, or every remote quarantined / filtered out → an empty merge): `log.Warn`, write nothing, return nil — the server starts empty and operates normally; because the table is still empty, the next boot retries (a transient peer outage at first boot self-heals on a later boot). The operator stops retries by unsetting `GT_SEED_SERVERS`.
- **Partial peer failure:** a peer that errors / times out has its votes dropped; the merge proceeds with the rest (subject to quorum), and whatever it adopts is written atomically.
- **Final summary:** one log line — `remotes adopted / tags adopted / tags quarantined / peers used (of configured) / duration`.

## 6. Testing

- **Unit — quorum merge:** agreement adopts; sub-quorum disagreement quarantines (+ logs); any-bad taint; taint-event union/dedupe; N=1 fast path.
- **Unit — chain rebuild:** genesis + per-taint observations produce a chain where `AssertChainIntact` holds; the ref projection matches the merged facts.
- **Atomicity / crash safety:** a Store wrapper whose `WithTx` errors partway through the write → assert the transaction rolled back, the `remotes` table is left empty, and a subsequent `Run` against healthy peers seeds fully (proving a crashed seed leaves no partial-stuck state).
- **Integration — seeder over `httptest` peers:** 2–3 stub peers serving canned `listRemotes`/`listTags`/`listTaintEvents`; assert the resulting store (real sqlite via `testutil`) matches the quorum result; cases: happy path, one poisoned peer (quarantined under N=2), one peer down (others still seed), allowlist filter, and the empty-DB-guard no-op on re-run. Run the fetch under `-race`.
- **Boot:** `git-taintedd` with `GT_SEED_SERVERS` pointing at a stub peer comes up with the seeded remotes; with the var unset, behaves exactly as today.

## 7. Out of scope / future

- The **byte-exact observation-ledger replay** + a `GET /v1/remotes/{id}/observations` (`/audit`) endpoint — the rebuilt-from-facts chain is tamper-evident going forward, so exact replay is a documented future extension (it would also serve standalone audit).
- **Batched-commit seeding for pathological fleets** — the atomic seed is one transaction; for a fleet of many thousands of remotes that becomes a large write set, a future variant could commit in bounded batches behind a completion marker (trading the simple all-or-nothing guarantee for incremental progress). Realistic deployments don't need it.
- **Continuous peer gossip / re-seeding** — this is one-shot bootstrap only; ongoing corroboration remains the verify CLI's query-time quorum.
- **Seeding through an auth-gated read proxy** — seeding uses the app's open read endpoints; if an operator fronts reads with a proxy that requires auth, carrying a seed credential is a future `GT_SEED_*` addition.
