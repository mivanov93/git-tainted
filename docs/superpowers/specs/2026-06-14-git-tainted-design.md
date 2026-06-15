# git-tainted — Design Spec

- **Status:** Approved design, implementation in progress
- **Date:** 2026-06-14
- **Author:** Mihail Ivanov
- **Repo:** `~/Projects/git-tainted` (forked from `tag-ledger`, then radically simplified)
- **Module:** `github.com/mivanov93/git-tainted`

> **Fork delta (what changed from `tag-ledger`):** dropped **Projects** (Remote is now the top entity; no cross-remote consolidation), dropped **branches** (no commit DAG, ancestry, or non-fast-forward taint), dropped **signatures** (and therefore *all* git object fetching — no treeless fetch, no tmpfs scratch, no `objectstore`). What remains: register a git **remote**, poll its **tags** with `git ls-remote`, record every tag→oid in an append-only, per-remote, SHA-256 hash-chained ledger, flag a tag **tainted** when its oid changes, and answer a **verify** query — plus a **CLI** (`git tainted`) that asks the question from inside a working repo.

---

## 1. Purpose

git-tainted detects when a git **tag** has been silently moved or rewritten on a remote. A tag is supposed to be an immutable pointer; if the oid a tag resolves to ever changes after we first saw it, that is a tamper/footgun signal. The service polls remotes, records each tag's oid over time in a tamper-evident ledger, and lets a client ask:

> "For remote R, is tag T still at the commit I have, and has it ever been tainted?"

It never checks out or downloads repository contents. The **only** git operation against a remote is `git ls-remote --tags`, which returns tag names + oids (and, for annotated tags, the peeled `^{}` commit oid) with **zero object downloads**.

## 2. Goals / Non-goals

**Goals**
- Register git remotes (ssh/https, any host) as the top-level tracked entity.
- Poll each remote's tags (scheduled + on-demand) and record every observed tag→oid.
- Append-only, per-remote, SHA-256 hash-chained observation ledger (tamper-evident audit).
- Detect & stick **taint** when a tag's oid changes after first observation, or it is deleted/recreated.
- A **verify** endpoint: `(remote, tag, commit?) → ok | tainted | mismatch | doesnt_exist | not_tracked` (+ `stale`).
- A **CLI** (`git tainted`) run inside a working repo: read `origin`'s URL, the tag at HEAD, and the commit, call the server, print a verdict, exit with a meaningful code.
- Wildcard tag search (glob default, optional RE2 regex).
- Run in Docker; all persistence behind a swappable `Store` (SQLite first); pure-Go static binaries.

**Non-goals**
- Branches, commit ancestry, non-fast-forward detection (removed).
- Signatures / signature verification (removed).
- Multi-remote mirror grouping / cross-remote divergence (removed — Remote is standalone).
- Downloading trees, blobs, or commit objects — ever (we never fetch objects at all now).
- App-level authentication (binds loopback; trusts an edge proxy).

## 3. Threat model & honest guarantees

git-tainted is **tamper-evidence under periodic sampling**, per remote, with **no cross-remote corroboration** (that was the dropped Projects feature).

**Detects**
- A tag whose oid (the tag-ref oid; for annotated tags the tag object, for lightweight the commit) changes after first observation → `tag_oid_changed`.
- A tag observed absent then present at a different oid → `tag_deleted_recreated`.
- A caller (CLI) whose local tag commit disagrees with the recorded peeled commit → `mismatch`.

**Cannot detect (documented, surfaced honestly)**
- **Within-interval transient tamper** (fundamental to polling): a tag moved and moved back to the exact prior oid *between* two polls is invisible — both `ls-remote` samples are identical. Mitigated only by shorter/jittered intervals.
- **Trust-on-first-observation, per remote**: with Projects/cross-remote removed there is no second witness; the first oid we record for a tag is taken as truth. If the tag was already tampered before we first saw it, we cannot know.
- **SHA-1 probabilistic immutability**: for sha1 repos `oid = content` is probabilistic (SHAttered-class); git's sha1dc detection is kept on, but the immutability claim is not cryptographically absolute. Prefer sha256 repos.

The README and the verify API docs state this plainly. (Re-introducing multiple remotes for corroboration is a possible future extension, explicitly out of scope here.)

## 4. Conceptual model

Four entities + one append-only spine.

- **Remote** — the top entity. A git remote URL we poll. Holds sync policy + health + its hash-chain head.
- **Tag** (a `ref` of kind tag) — a tag name under a remote, with its current/first oids and a sticky `tainted` flag. Per-remote projection, rebuildable from the ledger.
- **Observation** — the append-only, per-remote, hash-chained record of a tag-oid event (created / oid changed / deleted / recreated). `row_hash = SHA-256(prev_hash ‖ canonical(row))`, genesis = 32 zero bytes, advanced in the same txn as the insert.
- **TaintEvent** — immutable row recording why a tag became tainted (`tag_oid_changed` | `tag_deleted_recreated`). Taint is **sticky** (never auto-cleared); there is **no clear endpoint** (under no-app-auth an easy clear is an un-taint oracle); an append-only `ack` annotation is the only operator action.
- **Sync** — per-remote run audit (started/finished, status, counts, error, chain head before/after).

## 5. Decisions (locked)

| # | Decision |
|---|---|
| Language / git | **Go 1.26.4**, shelling out to the system `git` binary. **Only** `git ls-remote --tags` — no object fetch, no tmpfs, no `objectstore`. |
| Hardening (§ below) | exec argv (never a shell); strict URL validation (https + ssh only); `GIT_TERMINAL_PROMPT=0`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_ALLOW_PROTOCOL=https:ssh`, `--no-replace-objects -c core.useReplaceRefs=false`, hooks off, sha1dc on, per-call timeout + ctx-kill. (Object-size caps etc. are moot — we never fetch objects.) |
| Persistence | `Store` adapter; **SQLite (`modernc.org/sqlite`, pure-Go)** first. All timestamps BIGINT unix-ns. |
| Ledger | Append-only, per-remote, **SHA-256 hash-chained** observations; audit/verify endpoint. |
| Taint | `tag_oid_changed`, `tag_deleted_recreated`; sticky; ack-only (no clear). |
| Verify hash | Compare the **peeled commit oid** (the commit a checkout lands on). Annotated re-pointing still flagged via recorded tag-ref-oid history. |
| CLI on untracked remote | Return **`not_tracked`**; CLI exits non-zero with a register hint. CLI never makes the server fetch arbitrary URLs. |
| Sync | Scheduler (per-remote interval, jittered) + on-demand `POST /v1/remotes/{id}/sync`; per-remote `Lock` lease. |
| Auth | **None** (binds loopback; trusts an edge proxy). |
| Search | Glob default + optional RE2 regex. |
| Binaries | `cmd/git-taintedd` (server) + `cmd/git-tainted` (CLI — named so `git tainted` works as a git subcommand). Two binaries so the CLI stays lean (no SQLite/server deps). |

## 6. Sync engine

One writer per remote chain (per-remote `remote_lease` tied to a `chain_head` CAS; in-proc mutex for single-instance). Scheduler ticks every `GT_SCHEDULER_TICK_NS`, selects enabled remotes due (`last_ok_ns + sync_interval_ns < now`, jittered), runs up to `GT_SYNC_CONCURRENCY` under leases.

Per remote sync:
1. `git ls-remote --tags <url>` (hardened) → for each tag: ref oid, and for annotated tags the peeled `^{}` commit oid. Map by `refs/tags/*` only; store the short name; ignore other namespaces.
2. Diff vs the `refs` projection: new tag, oid changed, deleted, recreated.
3. Append observations (hash-chained, same-txn head CAS); update the `refs` projection; write a `syncs` audit row.
4. Taint at ingest: tag oid changed after first observation → `tag_oid_changed`; absent-then-different (or any deletion of an immutable tag, configurable) → `tag_deleted_recreated`. No change → no observation (append-on-change; `syncs` carries the heartbeat).

No object fetch ever. Steady state with no tag change = a single `ls-remote` and zero writes (besides the sync heartbeat row).

## 7. Verify state machine

`GET /v1/verify?remote=<url|id>&tag=<name>&commit=<oid>` — GET, read-only, never triggers a sync. `remote` accepts a normalized URL (looked up) or a remote id. `commit` optional.

- **`status`** (closed enum): `ok | tainted | mismatch | doesnt_exist | not_tracked`.
- **`confidence`** (freshness): `authoritative | stale` (stale when the remote's last sync failed or is older than `GT_STALENESS_BUDGET_NS`).

Input normalization (422 on bad input): `commit` (if given) must match `^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`, lowercase-canonicalized; never passed to git. `tag` rejects control chars / leading `-` / `..` / `@{` / `refs/...` (short name only).

Decision table (top-down). Let `C` = recorded peeled commit oid (for lightweight tags `C` = the commit/ref oid):

| condition | result |
|---|---|
| `remote` resolves to no tracked remote | `not_tracked` (HTTP 200) |
| tag name not present in that remote's tags | `doesnt_exist` |
| the tag is `tainted` (oid changed / deleted-recreated) | `tainted` (hash irrelevant) |
| clean, `commit` omitted | `ok` |
| clean, `commit == C` | `ok` |
| clean, `commit != C` | `mismatch` (your local tag's commit disagrees with the recorded one) |

`confidence=stale` is set orthogonally on any non-error result when the snapshot is stale. HTTP 200 for every logical verdict; 422 only for malformed input.

Response:
```jsonc
{
  "status": "ok|tainted|mismatch|doesnt_exist|not_tracked",
  "confidence": "authoritative|stale",
  "remote": { "id": 0, "normalized_url": "..." } | null,
  "tag": "v1.2.3",
  "recorded": { "ref_oid": "...", "peeled_commit_oid": "...", "first_seen_ns": 0, "last_seen_ns": 0 } | null,
  "supplied_commit": "..." | null,
  "taint": { "reason": "tag_oid_changed|tag_deleted_recreated", "first_tainted_at_ns": 0, "from_oid": "...", "to_oid": "..." } | null,
  "last_synced_ns": 0,
  "sync_outcome": "ok|failed|never",
  "ledger_proof": { "remote_id": 0, "seq": 0, "row_hash": "..." } | null
}
```

## 8. CLI — `git tainted`

A lean second binary (`cmd/git-tainted`), installable on PATH so `git tainted` works as a git subcommand. No SQLite/server imports — just an HTTP client + a thin git shell-out.

Behavior (run inside a working git repo):
1. Resolve the **remote URL**: `git remote get-url origin` (override: `--remote <name>` or `--url <url>`).
2. Resolve the **tag**: `git describe --tags --exact-match HEAD` (the tag pointing at HEAD; override: `--tag <name>`). If HEAD is not exactly at a tag, exit with a clear "not on a tag" message (override with `--tag`).
3. Resolve the **commit**: `git rev-parse HEAD^{commit}` (the peeled commit).
4. Call `GET {server}/v1/verify?remote=<url>&tag=<tag>&commit=<commit>`. Server from `GT_SERVER` env or `--server <url>` (default `http://127.0.0.1:8080`).
5. Print a human verdict (`--json` for machine output) and **exit code**:

| status | exit | message |
|---|---|---|
| `ok` (authoritative) | 0 | `ok: <tag> matches <remote> at <commit>` |
| `ok` (stale) | 0 (or 10 with `--strict`) | `ok (stale: last sync <age> ago)` |
| `mismatch` | 3 | `MISMATCH: <tag> on <remote> records <recorded-commit>, you have <commit>` |
| `tainted` | 4 | `TAINTED: <tag> on <remote> was rewritten (<reason> at <when>)` |
| `doesnt_exist` | 5 | `not found: <tag> is not a tag on <remote>` |
| `not_tracked` | 6 | `not tracked: <remote> is not registered with the server (ask an operator to add it)` |
| request/parse error | 2 | stderr diagnostic |

Hardening: the CLI validates the resolved URL the same way the server does before sending; it shells out to `git` with the hardened argv (no shell). It performs no writes.

## 9. Data model (SQLite first)

All PKs INTEGER surrogate; timestamps BIGINT unix-ns; oids BLOB (sha1=20B / sha256=32B; hex↔raw centralized). No SQLite-only features (GLOB search branches in Go for portability). **Removed from tag-ledger:** `projects`, `project_ref_state`, `commit_node`, `commit_edge`, `signatures`, `ref_signatures` (and the branch/peeled-DAG columns).

```sql
remotes(
  id PK, url TEXT NOT NULL, normalized_url TEXT NOT NULL UNIQUE,
  transport TEXT CHECK in('https','ssh'),
  sync_interval_ns BIGINT, staleness_budget_ns BIGINT,
  taint_any_tag_deletion INT DEFAULT 1, hash_algo TEXT CHECK in('sha1','sha256') NULL,
  status TEXT CHECK in('active','degraded','paused') DEFAULT 'active',
  last_ok_ns, last_err TEXT, consecutive_failures INT DEFAULT 0,
  chain_head_hash BLOB(32) NOT NULL, chain_len BIGINT DEFAULT 0,   -- genesis = 32 zero bytes
  removed_at_ns BIGINT NULL, created_at_ns, updated_at_ns)

refs(                              -- tags only; per-remote projection, rebuildable from observations
  id PK, remote_id FK NOT NULL, tag_name TEXT NOT NULL,
  current_oid BLOB, current_peeled_oid BLOB, is_annotated INT DEFAULT 0,
  first_oid BLOB, first_seen_ns, last_seen_ns, last_changed_ns,
  deleted INT DEFAULT 0, tainted INT DEFAULT 0, taint_first_ns BIGINT NULL,
  observation_count BIGINT DEFAULT 0,
  UNIQUE(remote_id, tag_name), INDEX(remote_id))

observations(                      -- APPEND-ONLY per-remote chain; no UPDATE/DELETE
  id PK, remote_id FK NOT NULL, ref_id FK NOT NULL, sync_id FK NOT NULL, seq BIGINT NOT NULL,
  event_type TEXT CHECK in('tag_created','tag_oid_changed','tag_deleted','tag_recreated'),
  prev_oid BLOB, new_oid BLOB, prev_peeled_oid BLOB, new_peeled_oid BLOB,
  observed_at_ns, prev_hash BLOB(32) NOT NULL, row_hash BLOB(32) NOT NULL, canonical_meta TEXT NULL,
  UNIQUE(remote_id, seq), INDEX(ref_id, observed_at_ns DESC))

taint_events(                      -- IMMUTABLE
  id PK, remote_id FK NOT NULL, ref_id FK NOT NULL,
  reason TEXT CHECK in('tag_oid_changed','tag_deleted_recreated'),
  observation_id FK NULL, from_oid BLOB, to_oid BLOB,
  detected_at_ns NOT NULL, acked_at_ns BIGINT NULL, acked_by TEXT NULL, ack_note TEXT NULL, detail TEXT,
  UNIQUE(remote_id, ref_id, reason, from_oid, to_oid))

syncs(
  id PK, remote_id FK NOT NULL, trigger TEXT CHECK in('register','scheduled','manual'),
  started_ns, finished_ns, status TEXT CHECK in('ok','partial','failed'),
  tags_seen INT, tags_changed INT, error TEXT,
  chain_head_before BLOB(32), chain_head_after BLOB(32))

remote_lease(remote_id PK, holder TEXT, acquired_at_ns, expires_at_ns)   -- Lock seam
```

Hash chain: `row_hash = SHA-256(prev_hash ‖ canonical(row))`, canonical = deterministic length-prefixed encoding of `(remote_id, seq, ref_id, event_type, prev_oid, new_oid, prev_peeled_oid, new_peeled_oid, observed_at_ns, canonical_meta)`; genesis 32 zero bytes; append + head advance in one txn.

## 10. API surface

OpenAPI 3.1, spec-first (Go server interface; the CLI uses a hand-written client). Loopback / no app auth.

- **Remotes (top):** `POST/GET/PATCH/DELETE /v1/remotes`. Body: `url`, `sync_interval_ns?`, `staleness_budget_ns?`, `taint_any_tag_deletion?`. `POST` 409 on duplicate `normalized_url`. `DELETE` soft (`removed_at_ns`; retain ledger). `GET /v1/remotes?url=<url>` resolves url→remote. `GET /v1/remotes/{id}/health`.
- **Sync:** `POST /v1/remotes/{id}/sync` (202). `GET /v1/remotes/{id}/syncs` (paginated).
- **Tags:** `GET /v1/remotes/{id}/tags?q=<glob>&regex=<re2>&tainted=any|only|never&limit=&cursor=` → tag projections with status. `GET /v1/remotes/{id}/tags/{name}` (detail + observation history).
- **Verify:** `GET /v1/verify?remote=<url|id>&tag=&commit=` (§7).
- **Audit:** `GET /v1/remotes/{id}/audit` (replay observations by seq, recompute the SHA-256 chain, compare to `remotes.chain_head_hash`). `GET /v1/remotes/{id}/taint-events`. `POST /v1/remotes/{id}/taint-events/{eid}/ack` (append-only annotation; does not clear).
- **Ops:** `GET /openapi.{json,yaml}`, `/healthz`, `/readyz`, `/metrics`, pprof.

All list endpoints take `limit` (default 100, max 1000) + opaque `cursor`; return `next_cursor`.

## 11. Configuration

Env-driven, prefix `GT_`: `DB_DRIVER=sqlite`, `SQLITE_PATH`, `LISTEN_ADDR` (loopback default), `SYNC_CONCURRENCY`, `SYNC_DEFAULT_INTERVAL_NS`, `SCHEDULER_TICK_NS`, `STALENESS_BUDGET_NS`, `GIT_BIN`, `GIT_TIMEOUT_NS`, `PROTOCOL_ALLOWLIST=https:ssh`, `LOG_LEVEL`, `METRICS_ADDR`. CLI: `GT_SERVER` (default `http://127.0.0.1:8080`).

## 12. Observability / ops

Structured `slog`; Prometheus metrics (sync duration, tags seen/changed/tainted, queue depth, verify latency, errors); pprof; `healthz`/`readyz`; graceful drain (finish in-flight sync, release leases). Two pure-Go static binaries; server image = `alpine:3.22` + `git`; the CLI ships as a standalone static binary.

## 13. Testing

golangci-lint v2, `go vet`, race detector, sqlc-diff, OpenAPI lint, Make smokes. Unit: URL validate/normalize; ls-remote parser (annotated dual-oid; tag namespace; short names); glob/RE2 + LIKE/GLOB escape; hash-chain compute/verify; observation diff/projection; verify state machine (every decision-table row); clock injection. Integration: a loopback `git http-backend` fixture repo with lightweight + annotated tags; sync, move a tag, re-sync → assert taint + chain intact + verify verdicts. CLI: a fixture repo + a stub/real server → assert each exit code path. E2e smoke (Make; pure-Go + local git, **no Docker** in the dev sandbox per the Docker Hub rate limit).

## 14. Removed from the tag-ledger fork (cleanup checklist)

Delete the packages/files and their references: `internal/objectstore/*`, `internal/git/signature.go`, `internal/git/revlist.go`, `internal/store/ancestry.go`, `internal/store/generation.go`, the commit-DAG sqlc (`dag.sql*`), and all signature/commit-DAG/project/branch code paths in `internal/sync`, `internal/store`, `internal/model`, `internal/api`. Drop schema tables `projects, project_ref_state, commit_node, commit_edge, signatures, ref_signatures` and the branch columns. Remove the `Project`/`CommitNode`/`CommitEdge`/`Signature` model types and the `AncestryStore`/`ProjectRefStateStore`/signature Store role interfaces. Rename module + binaries. Replace the OpenAPI spec, README, and these docs; remove the obsolete tag-ledger 8-phase plan from this repo.

## 15. Limitations (verbatim, surfaced in CLI + API docs)

1. **Within-interval transient tamper** — a tag moved and restored to the exact prior oid between two polls is invisible. Mitigate with shorter/jittered intervals.
2. **Trust-on-first-observation, per remote** — no cross-remote corroboration (Projects removed); the first oid recorded for a tag is taken as truth.
3. **SHA-1 probabilistic immutability** — sha1dc kept on; prefer sha256 repos.
4. **No tamper detection without polling coverage** — a remote never synced (or `not_tracked`) yields `not_tracked`, never a false `ok`.
