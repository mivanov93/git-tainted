# git-tainted — Seed-on-bootstrap (peer seeding) — Design Spec

- **Status:** Approved design (revised after adversarial review), not yet implemented
- **Date:** 2026-06-17
- **Author:** Mihail Ivanov
- **Repo:** `~/Projects/git-tainted`
- **Module:** `github.com/mivanov93/git-tainted`
- **Relates to:** [`2026-06-14-git-tainted-design.md`](2026-06-14-git-tainted-design.md) §3 (threat model) and [`2026-06-16-git-tainted-control-plane-design.md`](2026-06-16-git-tainted-control-plane-design.md) (auth: reads are never gated; the verify CLI's query-time quorum).
- **Revision:** revised 2026-06-17 after an adversarial design review (architecture-critic). See §9 changelog for what changed and why.

> **What this adds.** When a **new** server starts for the first time with `GT_SEED_SERVERS` set, it bootstraps itself from one or more **peer git-tainted servers** — adopting their remotes, current tag projections, and taint history — instead of starting blind (trust-on-first-observation from scratch). It reuses the peers' **existing read endpoints** (no new endpoint) and rebuilds its own local hash-chain from the imported facts. A configurable **quorum** turns seeding from a convenience bootstrap (N=1) into a corroboration defense (N>1).

---

## 1. Motivation & threat-model framing

A fresh server has no history: the first oid its own `ls-remote` returns for a tag becomes its truth (the §3 "trust-on-first-observation, per remote" limitation), so it cannot detect a tag that was already tampered *before* it started watching. Operators running a fleet (or replacing/adding a node) want a new server to inherit the fleet's existing baseline rather than re-establish trust from zero.

Seeding **shifts trust-on-first-observation from the new server's own `ls-remote` to the seed peers.** That is strictly better when the peers are older/trusted, and strictly worse if a seed peer is lying. `GT_SEED_QUORUM` (N) sets where on that spectrum you sit: N=1 trusts a single peer (convenience); N>1 requires **≥N peers to agree** before adopting any fact — a baseline oid, a taint, or a remote — so a sub-quorum minority of compromised peers cannot inject a fact. This mirrors the verify CLI's query-time multi-server quorum, applied at bootstrap.

**Honest posture (to be documented in the README §Honest posture).** Quorum bounds, but does not eliminate, peer trust:

- With **N=1** you fully trust the single peer — you inherit its blind spots and any pre-seed tamper it already trusted.
- Quorum protects fact *adoption* against a sub-quorum minority, but it **assumes the listed peers are independent** — it counts distinct URLs, not distinct operators, so N colluding or sybil peers behind different names defeat it. The config cannot enforce independence; the operator must choose genuinely independent seeds.
- A tag whose peers *disagree* (no value reaches N) is **quarantined** (not adopted). That is the safe choice, but it is also a **coverage-denial** lever: a minority that deliberately disagrees on many tags forces them untracked. Every quarantine is logged per-tag (with the disagreeing oids) so the operator can see exactly what was withheld.
- Seeding never weakens detection *going forward* — the rebuilt chain is tamper-evident and the new server's own `ls-remote` syncs continue normally; a quarantined or unseeded tag simply reverts to trust-on-first-observation from this server's first live sync.

## 2. Decisions (locked)

| # | Decision |
|---|---|
| Trust model | **Configurable quorum** `GT_SEED_QUORUM` (default **1**). A remote/tag fact (existence, `first_oid`, taint) is adopted only if **≥N** seed peers agree. N=1 = convenience; N>1 = corroboration. |
| Fidelity / endpoint | **Reuse the peers' existing read endpoints — NO new endpoint.** `listRemotes` + `listTags` (`first_oid`, `current_oid`, **`current_peeled_oid`**, `is_annotated`, `tainted`, `taint_first_ns`) + `listTaintEvents` (each taint's `from_oid→to_oid`+time). **Known fidelity gap:** the wire has no `first_peeled_oid` (nor per-observation peeled history), so for **annotated tags that have changed**, the genesis observation's *historical* peeled oid is unrecoverable — the chain is faithful in ref oids and best-effort in historical peeled oids. The **current** peeled oid *is* preserved (it's on the wire), which is what verify needs. Byte-exact ledger / `/audit` replay stays **out of scope** (§7). |
| Scope | **Mirror + allowlist.** Adopt *all* the peers' remotes by default; an optional `GT_SEED_REMOTES` glob restricts to a subset. |
| When | **First time only** — runs iff `GT_SEED_SERVERS` is set **and** the local `remotes` table has **zero rows** (incl. soft-deleted), re-checked **inside** the write transaction (§4.5) to close the TOCTOU. |
| Atomicity | **All-or-nothing, with a fail-loud ceiling** — the entire seed commits in **one transaction**; a crash rolls back to an empty table so the next boot re-seeds cleanly (no partial state, no marker). To bound the single-writer lock, the merge **refuses to commit and fails the seed loudly** above `GT_SEED_MAX_REMOTES` / `GT_SEED_MAX_OBSERVATIONS` rather than silently holding the lock (§7 has the batched-commit path beyond that). |
| Failure | **Best-effort** — a total failure (no peer reachable / quorum unmet / over-ceiling / write error → rollback) logs a warning and the server **starts empty**, never aborting startup; the next boot retries (the table is still empty). |
| Taint merge | **Quorum-gated** — a tag is adopted tainted only if **≥N** peers agree it is tainted (same threshold as `first_oid`), with the merged `from→to` oids and the earliest `taint_first_ns` among agreeing peers. *(Any-bad was rejected: seeded taints are written to the immutable, never-cleared spine, so one malicious peer under any-bad could permanently grief any tag.)* |
| Conflict | **Quarantine** — if no `first_oid` value, no taint verdict, or no coherent event sequence reaches N agreement, the tag is **skipped + logged per-tag**, not guessed. |
| Oid algo | **Resolved (fix `17fc588`).** The store now infers an oid's algo from its raw byte width at decode (`model.OIDFromRaw`), so seeded oids Just Work — the seed stores raw bytes and the decode labels them correctly; **no `hash_algo` from the wire is needed** and the seed needs no special algo handling. (Previously the decode hard-coded SHA-1, false-tainting every sha256 remote.) |
| Continuity | The rebuilt chain is **validated**: `from_oid[i] == to_oid[i-1]`, first `from_oid == first_oid`, and correct event types (deletions → `tag_deleted`/`tag_recreated`, not `tag_oid_changed`). A tag whose merged events don't form a coherent sequence is **quarantined**, never written as an incoherent (but hash-valid) chain. |
| Cadence | Adopt the peer's URL / transport / taint-policy, but use **this** server's default sync interval + staleness budget. |
| Auth | Seeding calls only the peers' **open read endpoints** (never gated per the control-plane auth design), so it needs no credentials even against an auth-enabled peer. |

## 3. Configuration (`internal/config`)

All new keys under `GT_SEED_*`; durations are `time.Duration` in code (env keeps the `_NS` ns wire name), per the duration convention.

| Env | Type | Default | Meaning |
|---|---|---|---|
| `GT_SEED_SERVERS` | string (comma/space list) | `""` | Peer base URLs. Empty ⇒ feature off. |
| `GT_SEED_QUORUM` | int | `1` | Min peers that must agree to adopt a remote/tag fact. |
| `GT_SEED_REMOTES` | string (comma globs) | `""` (all) | Optional allowlist filter on adopted remote URLs. |
| `GT_SEED_CONCURRENCY` | int | `8` | Max in-flight peer HTTP requests (bounded fan-out). |
| `GT_SEED_TIMEOUT_NS` | duration | `30s` | Per-request HTTP deadline. |
| `GT_SEED_INSECURE` | bool | `false` | Allow plaintext `http://` to non-loopback peers (mirrors the CLI guard; cross-host fleet peers fronted by plaintext h2c will need this). |
| `GT_SEED_MAX_REMOTES` | int | `5000` | Fail-loud ceiling on remotes in the one seed transaction. |
| `GT_SEED_MAX_OBSERVATIONS` | int | `200000` | Fail-loud ceiling on total observations in the one transaction. |
| `GT_SEED_MAX_PAGES` | int | `10000` | Per-resource pagination safety bound (a malformed peer can't drive an unbounded fetch loop). |

Validation (fail fast at startup): `GT_SEED_QUORUM >= 1` and `<= len(GT_SEED_SERVERS)` when servers are set (else no fact could be adopted); `GT_SEED_CONCURRENCY >= 1`; the ceilings `>= 1`.

## 4. Architecture

### 4.1 `internal/seed` package

A self-contained, injectable unit (no globals; testable):

```go
package seed

// Seeder bootstraps an empty store from peer servers. Constructed with an
// *http.Client (injectable for tests), the target model.Store, the resolved
// config, a model.Clock, and a logger.
type Seeder struct { /* client, store, cfg, clk, log */ }

// Run performs the one-shot bootstrap. NO-OP (nil) when seeding is disabled or
// the store already has remotes. Errors are logged, not fatal: Run returns nil
// on a best-effort empty seed so startup proceeds.
func (s *Seeder) Run(ctx context.Context) error
```

A thin **peer client** (same package) wraps the read endpoints with pagination + the transport guard, deserializing into local DTOs that mirror the `Remote`/`Tag`/`TaintEvent` wire shapes (it does **not** import `internal/api/oapi` — same lean pattern as the CLIs).

### 4.2 Boot wiring (`cmd/git-taintedd/main.go`)

After the store (and cache decorator) are ready and **before both the scheduler goroutine and the public HTTP listener** start (so no concurrent `POST /v1/remotes` races the seed; see §4.5 for the in-transaction guard that backstops this):

```go
if cfg.SeedEnabled() {
    if err := seed.New(httpClient, cached, cfg, clk, log).Run(ctx); err != nil {
        log.Error("seed bootstrap failed", "err", err) // non-fatal
    }
}
// ... then start the scheduler + HTTP server as today
```

Seeding writes through the **same cached `model.Store`** (the cache is empty at boot; invalidation is exercised harmlessly).

### 4.3 Fetch orchestration ("gazillion requests, prudently")

A single semaphore of size `GT_SEED_CONCURRENCY` shared across **all** peers:
1. Per peer, paginate `GET /v1/remotes`.
2. For each peer-remote (after the `GT_SEED_REMOTES` allowlist filter): paginate `GET /v1/remotes/{id}/tags` and `GET /v1/remotes/{id}/taint-events`.

**Pagination contract** (pinned — the endpoints differ): each list returns `next_cursor`; the client echoes it back as `cursor` and stops when `items` is empty **or** `next_cursor == 0`, whichever first (the cursor is a last-id keyset for `listTags` and a store offset for `listRemotes`/`listTaintEvents`, but the client treats it as opaque). `GT_SEED_MAX_PAGES` caps each resource's pagination. Every request is bounded by the semaphore + the per-request timeout. A peer that errors/times out is logged and **its votes are dropped** from the tally. HTTP/2/3 multiplexing + the peer's Otter cache keep the many small reads cheap; the semaphore keeps the fan-out bounded.

### 4.4 Quorum merge

All in memory. Keyed by **normalized remote URL**, then **tag name**. For each fact, "agree" means ≥N distinct peers report the same value.

- **Remote adoption:** adopt iff ≥N peers report the remote (post-allowlist). Adopt its URL/transport/taint-policy; cadence is local (§2).
- **`first_oid` (trust baseline) + algo:** group peers' `first_oid`; adopt the value with ≥N agreement, else **quarantine**. The oid's **algo is inferred from hex length** (40→sha1, 64→sha256) and carried through (§8). Also adopt the agreed `is_annotated` and the freshest agreeing peer's `current_oid` + **`current_peeled_oid`** (interim — overwritten by the first live sync; only `first_oid` is durable).
- **Taint (quorum-gated):** the tag is tainted iff ≥N peers report `tainted=true`. Merge their taint events (union, deduped by `(from_oid,to_oid,detected_at_ns)`, ordered by `detected_at_ns`); take the earliest `taint_first_ns`. A taint reported by < N peers is **not** adopted (the tag is treated clean — sub-quorum taint is a quarantine candidate if peers conflict, else dropped).
- **Continuity validation (before any write):** the merged `created → events…` sequence must chain — first event's `from_oid == first_oid`, each `from_oid[i] == to_oid[i-1]` — and deletions (`to_oid` empty) must map to `tag_deleted`/`tag_recreated`, not `tag_oid_changed`. A sequence that doesn't validate is **quarantined**.

(N=1 collapses agreement to "the single peer's value"; quarantine then only triggers on an internally-incoherent single-peer sequence.)

### 4.5 Atomic write — local chain rebuild in one transaction

Fetch + merge + continuity-validation run **in memory** (no DB writes; no txn during network I/O). The validated result is then written in **one `store.WithTx`** (all-or-nothing, §2). The hash-chain's canonical row embeds the **local** `remote_id` (`store/chain.go`), so peer row-hashes don't transfer; the server rebuilds its own chain. Inside the transaction:

0. **Re-check the guard:** count `remotes` rows (incl. soft-deleted) **inside the txn**; if non-zero (a concurrent create slipped in), abort — closes the §2 "When" TOCTOU.
0b. **Ceiling check:** if `len(remotes) > GT_SEED_MAX_REMOTES` or total observations `> GT_SEED_MAX_OBSERVATIONS`, abort loudly (don't hold the writer for an unbounded seed).

Then per adopted remote:
1. `tx.CreateRemote(...)` — assigns the local id. **Seam change:** `CreateRemote` joins the `model.Tx` interface (sqlite/mysql tx types + the cache `captureTx`, which on commit bumps the **set-generation** only — mirroring the top-level `cache.CreateRemote`; a brand-new remote has nothing cached, so no per-remote gen bump). The normal API path keeps using `Store.CreateRemote`.
2. Per adopted tag, in this order (matching the live path `internal/sync/remote.go`, which upserts the ref **first** to get `ref.ID`):
   a. **Upsert the ref projection** to establish `ref.ID`, `first_oid`, `first_seen_ns`, `is_annotated` (`UpsertRef`'s `DO UPDATE` does *not* touch `first_oid`/`first_seen_ns`, so this first upsert must carry them correctly).
   b. **Genesis observation** — `event_type=created`, `new_oid=first_oid`, `new_peeled_oid=current_peeled_oid` **iff the tag never changed** (no taint events) else best-effort/empty (the historical peeled oid is unrecoverable, §2 fidelity gap), `observed_at_ns=first_seen_ns`, `canonical_meta=""` (the live path never sets it), `ref_id=ref.ID` — advancing the chain from the 32-zero genesis via `chain.go` + `tx.AdvanceChainHead`.
   c. **One observation per merged taint event**, with the **correct event type** (`tag_oid_changed`, or `tag_deleted`/`tag_recreated` for deletions), `prev_oid→new_oid` from the validated continuous sequence, `observed_at_ns=detected_at_ns`; plus the matching `taint_events` row; each advancing the chain.
   d. **Final upsert** of the ref projection: `current_oid`, `current_peeled_oid`, `tainted`, `taint_first_ns`, `observation_count` = appended-observation count.

This reuses `store.WithTx`, `chain.go`, and the existing append/advance `Tx` methods; the only new persistence primitive is `Tx.CreateRemote` (+ the `CountAllRemotes` query, §8). `testutil.AssertChainIntact` **and** an oid-continuity + event-type assertion must hold for every seeded remote (§6).

### 4.6 After seeding

The scheduler starts; the new server's own `ls-remote` produces the live observation per tag. Because the seeded `first_oid` is the chain's baseline, a live oid that diverges from it correctly produces a `tag_oid_changed` taint — the new server immediately detects a tag that moved between the peers' last sight and its own first sight. Already-tainted (sticky) tags stay tainted. (This is the window §2's algo-prerequisite protects: a seeded sha256 baseline must `OID.Equal` the live sha256 oid, or every unchanged tag false-taints.)

## 5. Error handling & idempotency

- **First-time guard:** `Run` no-ops unless `GT_SEED_SERVERS` is set and `remotes` has **zero rows** (incl. soft-deleted, so a fleet later emptied never silently re-seeds), re-checked **inside** the write txn (§4.5 step 0).
- **Atomicity — the crash story:** fetch + merge + validation build the full result in memory; the writes go through **one `store.WithTx`**. A crash/kill/OOM/reboot at any point leaves `remotes` empty (txn never opened or rolled back), so the **next boot re-seeds cleanly**. No partial fleet, no marker. Restarting *during* seeding is identical.
- **Total failure** (no peer reachable, everything quarantined/filtered, or over-ceiling): `log.Warn`, write nothing, return nil — server starts empty; the next boot retries. Operator stops retries by unsetting `GT_SEED_SERVERS`.
- **Partial peer failure:** that peer's votes drop; the merge proceeds with the rest (subject to quorum).
- **Per-tag quarantine logging:** each quarantine logs `remote_url + tag_name + the per-peer oid/taint disagreement` at `Warn` — actionable, not just a count.
- **Final summary:** one line — `remotes adopted / tags adopted / tags quarantined / peers used (of configured) / duration`.

## 6. Testing

- **Unit — quorum merge:** ≥N agreement adopts; sub-quorum disagreement quarantines (+ logs the oids); **quorum-gated taint** (adopted only at ≥N; sub-quorum taint dropped); taint-event union/dedupe/order; N=1 fast path; allowlist filter; **algo inference** (40-hex→sha1, 64-hex→sha256).
- **Unit — chain rebuild + continuity:** genesis + correctly-typed per-event observations produce a chain where `AssertChainIntact` holds **and** oid-continuity holds (`from[i]==to[i-1]`, first `from==first_oid`); a deliberately-discontinuous merged sequence is **quarantined, not written**; deletions become `tag_deleted`/`tag_recreated`. The §2 fidelity gap is pinned: an annotated tag with taint history gets a best-effort genesis peeled oid but a correct *current* peeled oid.
- **Unit — verify correctness after seed:** a seeded **annotated** tag, queried via `Verify` with the real peeled commit, returns `ok` (not `mismatch`) — guards C1.
- **Unit — algo round-trip:** a seeded **sha256** remote, re-read and compared (`OID.Equal`) against a fresh sha256 oid of the same bytes, is equal (guards C2 / the §8 prerequisite).
- **Atomicity / crash safety:** a Store wrapper whose `WithTx` errors partway → assert rollback, `remotes` empty, and a subsequent `Run` seeds fully. Plus the in-txn guard: a remote present at txn-start aborts the seed.
- **Integration — seeder over `httptest` peers:** 2–3 stub peers; assert the resulting real-sqlite store matches the quorum result; cases: happy path, one poisoned peer quarantined under N=2, **one peer fabricating a taint that is NOT adopted under N=2** (M1), one peer down, allowlist, empty-DB-guard no-op on re-run. Fetch under `-race`.
- **Boot:** `git-taintedd` with `GT_SEED_SERVERS` → comes up seeded; unset → behaves exactly as today.

## 7. Out of scope / future

- **`first_peeled_oid` on the wire / byte-exact observation-ledger replay** (`/audit` endpoint) — would close the §2 annotated-tag fidelity gap and enable exact chain replay; deferred per the "no new endpoint / reuse existing reads" decision.
- **Batched-commit seeding above the ceiling** — beyond `GT_SEED_MAX_*`, a future variant could commit in bounded batches behind a completion marker (trading the simple all-or-nothing guarantee for incremental progress). Today the ceiling fails loudly instead.
- **Continuous peer gossip / re-seeding** — one-shot bootstrap only; ongoing corroboration remains the verify CLI's query-time quorum.
- **Seeding through an auth-gated read proxy** — uses the app's open read endpoints; a credential for a read-gating proxy is a future `GT_SEED_*` addition.

## 8. Prerequisites & companion changes (must land with, or before, the seeder)

- **Algo-aware oid decode (C2) — ✅ DONE (`17fc588`).** `model.OIDFromRaw` now infers the algo from raw byte width (sha1=20, sha256=32 — they never collide) across both store backends, fixing the pre-existing sha256 false-taint bug (the store had hard-coded SHA-1 everywhere). The seed therefore needs **no** special algo handling: it stores raw oid bytes and the decode labels them correctly. *(Open testing-gap follow-up: the git-server testutil only makes sha1 repos — no `--object-format` — which is why this was never caught; closing it enables an end-to-end sha256 sync regression test.)*
- **`Tx.CreateRemote`** added to the `model.Tx` seam (sqlite/mysql tx + cache `captureTx`).
- **`CountAllRemotes(ctx) (int64, error)`** store/query (counts incl. soft-deleted) for the first-time guard — there is no existing remotes count query.
- **README §Honest posture** updated with the §1 seeding caveats (peer independence, quarantine coverage-denial, N=1 full trust).

## 9. Changelog (post-review revisions, 2026-06-17)

Revised after an adversarial architecture review. Material changes from the first draft:
- **Taint merge: any-bad → quorum-gated** (M1) — any-bad let one malicious peer write a permanent immutable taint.
- **C1 peeled oid** — copy `current_peeled_oid`/`is_annotated`; genesis peeled best-effort; documented the annotated-tag fidelity gap (else seeded annotated tags verify as `mismatch`).
- **C2 algo** — infer algo from hex length + the algo-aware-decode prerequisite (§8) (else seeded sha256 oids false-taint on first sync).
- **C3 ordering** — upsert the ref *before* appending observations (the observation needs `ref.ID`).
- **C4 continuity** — validate oid-continuity + correct deletion event types; quarantine incoherent sequences (a hash-valid chain can still be semantically broken; `AssertChainIntact` alone is too weak).
- **M2 guard** — re-check zero-rows *inside* the write txn (TOCTOU); added `CountAllRemotes`; seed before the HTTP listener too.
- **M3 ceiling** — kept whole-fleet atomic, added fail-loud `GT_SEED_MAX_*` ceilings.
- **M4 pagination** — pinned the stop condition + per-endpoint cursor semantics + `GT_SEED_MAX_PAGES`.
- Honest-posture rewrite (sybil/independence, quarantine coverage-denial); per-tag quarantine logging.
