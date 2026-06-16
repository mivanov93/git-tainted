# git-tainted — Control-plane: Auth + Control CLI + Hot-path Cache — Design Spec

- **Status:** Approved design, implementation in progress
- **Date:** 2026-06-16
- **Author:** Mihail Ivanov
- **Repo:** `~/Projects/git-tainted`
- **Module:** `github.com/mivanov93/git-tainted`
- **Amends:** [`2026-06-14-git-tainted-design.md`](2026-06-14-git-tainted-design.md) §2 (Non-goals), §5 (Decisions). This document is authoritative for the three features below.

> **What this adds.** Three control-plane features on top of the shipped verify/sync core:
> **(A)** *optional* authentication on the mutating "control" endpoints — `none` (default) / `apikey` / `basic` / `jwks`;
> **(B)** a third binary, **`git-tainted-ctl`**, the admin CLI that registers/configures remotes and drives sync/taint operations against those endpoints;
> **(C)** an **Otter**-backed caching `Store` decorator on the verify hot path, with **per-remote generation** invalidation so a renewed tag/taint/health is never served stale beyond a bounded TTL.

---

## 1. Purpose & guiding constraints

The shipped server (2026-06-14) binds loopback and trusts an edge proxy; the only client is the read-only `git tainted` verify CLI; every verify request hits the DB. This spec closes three gaps a real deployment hits:

1. **No app-level auth** — fine behind a trusted proxy, but a direct-exposure deployment needs the *write* surface (register/delete/reconfigure remotes, trigger sync, ack taint) gated without putting reads behind a wall (open verification is the product's value).
2. **No first-class admin client** — configuring remotes today means hand-rolled `curl`. Operators need a lean, scriptable CLI symmetric with `git tainted`.
3. **Verify re-reads the DB every call** — the hot path is three indexed reads per request; under fan-out from many CLIs that is the dominant cost. A correctness-preserving cache removes it.

**Constraints carried from the core (unchanged):** Go 1.26.4, CGO-free pure-Go static binaries; two-impls-per-interface seams, all defaulting to in-memory so the server runs with **no Redis/external deps**; all timestamps BIGINT unix-ns; the lean verify CLI must not gain server/SQLite deps. Owner directives: latest/LTS deps; no silent scope cuts; no agent pushes; commits carry no attribution trailer.

---

## 2. Feature A — Optional auth on the control endpoints

### 2.1 Decision & posture

Auth is **opt-in**, default `none`. `none` reproduces today's behavior exactly (loopback + edge-proxy trust), so this is additive, not a breaking reversal of the §5 "Auth: None" decision — it becomes "None by default; apikey/basic/jwks available." Reads are **never** gated; only the five mutating operations are.

### 2.2 Protected vs open

| Gated (control) | Open (always) |
|---|---|
| `POST   /v1/remotes` (createRemote) | `GET /v1/verify` |
| `PATCH  /v1/remotes/{id}` (updateRemote) | `GET /v1/remotes` (listRemotes) |
| `DELETE /v1/remotes/{id}` (deleteRemote) | `GET /v1/remotes/{id}` (getRemote) |
| `POST   /v1/remotes/{id}/sync` (triggerSync) | `GET …/syncs`, `…/tags`, `…/tags/{t}`, `…/taint-events` |
| `POST   /v1/remotes/{id}/taint-events/{eid}/ack` (ackTaintEvent) | `GET /healthz`, `/readyz` |

The protected set is the canonical list of operationIds — defined once as `auth.ControlOperations` (a `map[string]bool`) so it can't drift from the router.

### 2.3 Configuration

- `GT_AUTH_MODE` = `none` (default) | `apikey` | `basic` | `jwks`. Unknown value → fatal config error at startup.
- **apikey:** `GT_API_KEYS` (comma-separated raw keys; each SHA-256-hashed at load, raw discarded) and/or `GT_API_KEYS_SHA256` (comma-separated lowercase-hex SHA-256 digests; raw key never enters the server env). At least one key required when mode=apikey. Client presents `Authorization: Bearer <key>` **or** `X-API-Key: <key>`. Compare = constant-time over the SHA-256 digest against the configured set.
- **basic:** `GT_BASIC_AUTH` = comma-separated `user:bcrypt-hash` entries (htpasswd-style; raw passwords never in server env). At least one entry required. Client presents standard HTTP Basic; verify with `bcrypt.CompareHashAndPassword`. Unknown user → same generic 401 as bad password (no user-enumeration oracle), still constant-time-ish (run a dummy bcrypt to flatten timing when the user is unknown).
- **jwks:** `GT_JWKS_URL` (required); `GT_JWT_ISSUER`, `GT_JWT_AUDIENCE` (required — empty disables that claim check is **not** allowed; both must be set so tokens can't be replayed cross-audience); `GT_JWT_ALGS` (default `RS256,ES256`; an allowlist — `none` and HS* are always rejected). Verify: signature against a JWKS keyed by `kid`, plus `exp`, `nbf`/`iat` (small skew leeway, e.g. 60s), `iss`, `aud`. Client presents `Authorization: Bearer <jwt>`.

### 2.4 The `internal/auth` seam

```go
package auth

// Authenticator verifies a request's credentials for a control operation.
// principal is a stable identity string for audit (key-id, username, or JWT sub);
// err is a typed auth failure (never a 5xx) — the middleware maps it to 401.
type Authenticator interface {
    Authenticate(r *http.Request) (principal string, err error)
    // Challenge is the WWW-Authenticate value for 401s ("Bearer", `Basic realm="git-tainted"`, …).
    Challenge() string
}
```

Implementations (two-impls spirit — all selectable, default memory-only): `noneAuth` (always allows, principal `"anonymous"`, empty challenge), `apiKeyAuth`, `basicAuth`, `jwksAuth`. A `FromConfig(cfg) (Authenticator, error)` constructor selects + validates. `jwksAuth` owns a refreshing JWKS cache (background refresh on TTL + on-demand fetch when an unknown `kid` arrives, rate-limited to avoid a fetch-amplification DoS).

### 2.5 Enforcement

`NewServer` gains an `Authenticator` parameter. Enforcement is a middleware that runs **before** the strict handler / any Store call: for a request whose matched operation is in `ControlOperations`, it calls `Authenticate`; on error it writes `401` + `WWW-Authenticate: <Challenge()>` and a JSON `{"error":"unauthorized"}` body and returns — the handler and Store are never reached. The matched operation is determined by a dedicated control-route `http.ServeMux` populated with the five generated patterns (reuses ServeMux's exact pattern matching incl. `{id}` wildcards), so the protected set is precise and table-driven. `none` mode wraps with a pass-through (zero overhead on the open path; the middleware is still installed so the wiring is uniform and testable).

On success the principal is added to the request context; mutation handlers log it, and `ackTaintEvent` uses it as the default `acked_by` when the body omits one.

### 2.6 Dependencies

- `github.com/lestrrat-go/jwx` (latest stable major) — JWKS fetch/cache + JWT verify.
- `golang.org/x/crypto/bcrypt` — basic-auth hashes.

### 2.7 Errors & edge cases

- Missing/empty credential, malformed header, wrong scheme → `401` + challenge (never 400).
- Mode misconfig (apikey with no keys, jwks with no URL/issuer/audience, basic with no users, bad bcrypt hash) → fatal at startup, not per-request.
- JWKS endpoint down at request time → `401` (fail-closed) with a logged warning; never 5xx (an attacker mustn't distinguish "down" from "denied" via status, and the control plane must not open up because the IdP blipped).
- Auth never applies to `OPTIONS`/preflight on open routes (there are none cross-origin today; documented).

### 2.8 Tests

Table-driven `internal/auth` unit tests per mode (valid/invalid/missing/expired/wrong-aud/unknown-kid/alg-not-allowed/timing-shape); a server-level test asserting **every** control op 401s without creds and 200/2xx with, and **every** open op is reachable with no creds, across all four modes; a jwks test with a local in-memory JWKS + signed tokens (no network). Negative: `alg:none` and HS256-signed token both rejected under jwks. The existing pentest suite (`make pentest`) gains an "auth modes" section.

---

## 3. Feature B — `git-tainted-ctl` (control CLI)

### 3.1 Shape

New binary `cmd/git-tainted-ctl`, **lean** like `cmd/git-tainted`: stdlib `flag` subcommands (no cobra), no `internal/api/oapi` import (thin local wire structs mirroring the JSON, same pattern as the verify CLI's `verifyResponse`), reuses `internal/buildinfo` and `internal/git` URL validation. Testable `run(args, environ, stdout, stderr) int`.

### 3.2 Commands

| Command | HTTP | Notes |
|---|---|---|
| `remote add <url> [--interval <dur>] [--disabled]` | `POST /v1/remotes` | prints new id |
| `remote list [--json]` | `GET /v1/remotes` | table or JSON; `--limit`, `--cursor` |
| `remote get <id\|url> [--json]` | `GET /v1/remotes/{id}` or `GET /v1/remotes?url=` | url form uses the list-by-url filter |
| `remote update <id> [--interval <dur>] [--enabled=<bool>]` | `PATCH /v1/remotes/{id}` | only sends provided fields |
| `remote rm <id>` | `DELETE /v1/remotes/{id}` | |
| `sync <id>` | `POST /v1/remotes/{id}/sync` | trigger; prints 202 acceptance |
| `syncs <id> [--limit] [--json]` | `GET …/syncs` | audit convenience (read) |
| `tags <id> [--json]` | `GET …/tags` | convenience (read) |
| `taint list <id> [--json]` | `GET …/taint-events` | |
| `taint ack <id> <eventId> [--note <s>] [--by <s>]` | `POST …/taint-events/{eid}/ack` | |

Global flags: `--server` (`GT_CTL_SERVER`, default `http://127.0.0.1:8080`), `--json`, `--timeout` (default 10s), `--insecure` (`GT_CTL_INSECURE`), `--version`/`-v`, `--help`/`-h`, plus per-command `--help`.

### 3.3 Auth sending

Mirrors the server modes, auto-selected from whichever is set (explicit flag wins over env):
- `--api-key` / `GT_API_KEY` → `Authorization: Bearer <key>` (and `X-API-Key`).
- `--token` / `GT_TOKEN` (a pre-obtained JWT) → `Authorization: Bearer <jwt>`.
- `--basic` / `GT_BASIC_AUTH=user:pass` → `Authorization: Basic …`.
- none set → no auth header (works against `GT_AUTH_MODE=none`).

Same transport guard as the verify CLI: refuse plaintext `http://` to a non-loopback host unless `--insecure`/`GT_CTL_INSECURE` (sending an API key/JWT in clear to the network is worse than a read).

### 3.4 Exit codes

`0` ok · `2` usage/transport/parse · `3` not-found (404) · `4` unauthorized/forbidden (401/403) · `5` conflict (409, e.g. duplicate remote) · `6` server error (5xx). Human + `--json` output for every command.

### 3.5 Tests

`run(...)`-level tests against an `httptest.Server` stub asserting method/path/body/headers per command, auth-header selection per mode, exit-code mapping per status, `--json` shape, and `--version`/`--help`. No real network/git.

---

## 4. Feature C — Otter caching `Store` decorator

### 4.1 What is cached

The `Verify` hot path issues, per request: `GetRemoteByURL` **or** `GetRemote` → `GetRef` → `LatestObservationForRef`. Plus `ListTags` (tag listing) is read-heavy. The decorator caches exactly these read methods; all other reads (audit lists, chain replay) and **all writes** pass straight through.

### 4.2 The decorator

`internal/store/cache`: a `cachingStore` implementing `model.Store`, constructed `cache.Wrap(inner model.Store, cfg) model.Store`. It embeds/holds `inner` and delegates everything, overriding only the cached reads + the writes that must invalidate. Otter caches (bounded, TTL'd) hold the read results. Default-on; a disabled config returns `inner` unwrapped (zero overhead, identical behavior) so the seam is provably transparent.

### 4.3 Invalidation = per-remote generation counters

A flat KV cache (Otter) can't enumerate keys by remote, so invalidation uses **generations**:

- A `gens` map `RemoteID → uint64` (lock-free: `xsync`/`sync.Map` of atomics, or an Otter cache). `genOf(id)` returns the current generation (0 if absent).
- Every cached key embeds its remote's generation: e.g. `ref|<remoteID>|<gen>|<tag>`, `lobs|<refID>|<remoteGen>`, `tags|<remoteID>|<gen>`, `remote|<remoteID>|<gen>`.
- **Invalidating a remote = atomically incrementing `gens[id]`.** All its prior-gen keys become unreachable instantly; Otter's S3-FIFO eviction reclaims the orphans lazily; the TTL bounds any orphan lifetime regardless.
- A small **URL→ID index** cache (`byurl|<normURL>|<setGen>` → RemoteID) lets `GetRemoteByURL` resolve the id then reuse the per-remote `remote|id|gen` entry. A **remote-set generation** (`setGen`, one global atomic) backs `ListRemotes` and the URL→ID index; it is bumped only on **create/delete** (membership changes), not on every update/sync.

**Write surfaces and what they bump** (always **after** the underlying write returns success):

| Write | Bumps |
|---|---|
| `WithTx(fn)` (sync path) | each **touched remoteID** (see 4.4) |
| `UpdateRemote` | that remote's gen |
| `SoftDeleteRemote` | that remote's gen **and** `setGen` |
| `CreateRemote` | `setGen` |
| `SetRemoteHealth` | that remote's gen (last_ok_ns feeds verify staleness) |
| `SetRefTaint` | that ref's remote's gen |

### 4.4 Capturing touched remotes inside `WithTx`

`WithTx` takes a closure that receives a `Tx`; the decorator passes a **wrapping `Tx`** that delegates to the real tx and records the set of remoteIDs it observes: `AppendObservation(o)` → `o.RemoteID`; `UpsertRefProjection(ref)` → `ref.RemoteID`; `AdvanceChainHead(remoteID,…)` → `remoteID`; `AppendTaintEvent(e)` → `e.RemoteID`. On the real `WithTx` returning **nil** (commit succeeded), the decorator bumps every recorded remote's gen. On error (rollback), it bumps nothing (cache still reflects committed state). The recorded set lives on the per-call wrapper, so concurrent transactions don't share it.

**RefID-keyed methods (`LatestObservationForRef`, `SetRefTaint`) — validated against `internal/sync/remote.go`.** A ref's owning remote is immutable, so the decorator keeps a lazily-populated, **never-invalidated** `refID→remoteID` index (filled by `GetRef`, which returns `ref.ID`+`ref.RemoteID`, and by the `ObservationProof.RemoteID` returned on a `LatestObservationForRef` miss). `LatestObservationForRef(refID)` is keyed `(refID, gen[remoteID])` via that index. Crucially, the **live sync path applies taint *inside* `WithTx`** — `tx.UpsertRefProjection(ref)` (sets the `Tainted` flag, carries `RemoteID`) + `tx.AppendTaintEvent(e)` (carries `RemoteID`) — so a tag becoming tainted is **already covered** by the per-remote capture above; no separate hook is needed. `SetRefTaint` is interface-only (not on the live sync/verify path today), but the decorator still overrides it defensively: resolve the remote via the index and bump, or no-op if the ref was never cached.

### 4.5 Correctness (locked rule)

**Bump-gen strictly *after* the underlying write commits.** Then for any concurrent `Verify`:
- It reads the DB and caches under the **old** gen *before* the writer commits → it cached a pre-write value under a gen that the bump then orphans → next read misses → re-reads fresh. (At worst one redundant fill; never a stale serve.)
- It reads *after* the bump → it sees the **new** gen → miss → fresh read.

There is no ordering in which a post-commit value is served under a live gen beyond the cache TTL. The TTL is the backstop for any pathological interleaving and for liveness if a bump is ever missed. This is the single invariant the implementation and its tests must protect.

### 4.6 Configuration

- `GT_CACHE_ENABLED` (default **true**). When false, `cache.Wrap` returns `inner` unchanged.
- `GT_CACHE_MAX_ENTRIES` (default e.g. 100_000) — Otter capacity (per logical cache or a shared budget).
- `GT_CACHE_TTL_NS` (default e.g. 60_000_000_000 = 60s) — staleness backstop; independent of generation invalidation (which is immediate).

### 4.7 Concurrency & deps

Lock-free reads/writes (Otter is lock-free; gens are atomics). No added goroutines except Otter's internal maintenance. Dep: `github.com/maypok86/otter` (latest stable).

### 4.8 Tests

Unit tests on `cachingStore` with a fake `inner` (call-counting): a cached read hits `inner` once then serves from cache; each write surface bumps the right gen and forces the next read to miss; the `WithTx` wrapper bumps exactly the touched remotes and nothing on rollback; `GetRemoteByURL` reuses the per-remote entry; disabled-config is pass-through. A **race/correctness test** under `-race`: concurrent verifiers + a writer asserting no verifier observes a value older than the last committed write beyond TTL=0 (TTL set to 0 in the test to prove generation invalidation alone is sufficient). The existing store integration suite runs unchanged through the decorator (behavioral equivalence).

---

## 5. Amendments to the 2026-06-14 spec

- **§2 Non-goals** — strike "App-level authentication (binds loopback; trusts an edge proxy)." Replace with: auth is **opt-in** (default `none` preserves the loopback/edge-proxy posture); `apikey`/`basic`/`jwks` gate only the mutating control endpoints.
- **§5 Decisions** — `Auth` row → "Default **None** (loopback/edge-proxy trust); optional `apikey`/`basic`/`jwks` on the five control endpoints (`internal/auth` seam)." Add `Cache` row → "Otter caching `Store` decorator on the verify hot path; per-remote generation invalidation, bump-after-commit; default-on, TTL-backstopped, fully disableable." `Binaries` row → add `cmd/git-tainted-ctl` (admin CLI; lean, no server/SQLite deps).

---

## 6. Build sequence & gates

Independent, no-push + repo-guarded sub-agents, each gated to green before the next depends on it:

1. **Auth** — `internal/auth` + config + `NewServer`/`main` wiring + tests. Touches `config.go`, `server.go`, `main.go`.
2. **Control CLI** — `cmd/git-tainted-ctl` + tests. Disjoint files → runs **in parallel** with Auth.
3. **Caching** — `internal/store/cache` + config + `main` wiring + tests. Shares `config.go`/`main.go` with Auth → runs **after** Auth lands.

**Per-feature gate (all must pass, none skipped):** `go mod tidy` clean; `make sqlc` / `make oapi-server` no drift; `make lint` (golangci-lint v2) = 0; `go vet ./...`; `go test ./... -count=1`; `go test -race -count=1 ./...`; `make e2e`; `make build` (all three binaries); `deadcode -test -tags=e2e ./...` empty; `make test-mysql` against the **cached** `mysql:8.4` for store-touching changes. New env vars land in `.env.example` + the server `--help`. Commits are plain Conventional Commits, **no attribution trailer, no push** (owner pushes).

## 7. Out of scope / future

Per-key scopes/RBAC (all control ops share one gate now); auth on reads; rate-limiting per principal; OIDC discovery (`/.well-known`); cache metrics wired to the Prometheus registry (could expose hit/miss once metrics are enabled); distributed cache (single-instance only — matches the in-proc lease model).
