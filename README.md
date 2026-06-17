# git-tainted

Tamper-evidence for git **tags**. A tag is supposed to be an immutable pointer — if
the commit a tag resolves to ever changes after it was first seen, that's a tamper or
a footgun (a moved release tag, a force-rewritten `v1.2.3`). `git-tainted` watches
remotes for exactly that and lets you check, from inside a working repo, whether your
checked-out tag is still legitimate.

It never clones or downloads repository contents. The only thing it asks a remote is
`git ls-remote --tags` (tag names + oids, **zero objects**), records every tag→oid
over time in an append-only, per-remote, **SHA-256 hash-chained** ledger, and flags a
tag **tainted** the moment its oid changes.

> "For remote R, is tag T still at the commit I have, and has it ever been moved?"

## Three binaries

| Binary | Purpose |
|--------|---------|
| `git-taintedd` | Server — polls remotes, maintains the tamper-evident ledger, serves the API |
| `git-tainted` | Verify CLI — run inside a working repo; exits with a meaningful code |
| `git-tainted-ctl` | Admin CLI — register / configure remotes, trigger syncs, manage taint events; authenticates to the [control endpoints](#authentication) |

`git-tainted` is named so that `git tainted` works as a git subcommand when it is on
your `PATH`.

## Install

```sh
# Verify CLI — becomes `git tainted` once on your PATH
go install github.com/mivanov93/git-tainted/cmd/git-tainted@latest

# Admin CLI — register/configure remotes, trigger syncs, ack taints
go install github.com/mivanov93/git-tainted/cmd/git-tainted-ctl@latest

# Server
go install github.com/mivanov93/git-tainted/cmd/git-taintedd@latest
# or from a clone:  make build   →   bin/git-taintedd, bin/git-tainted, bin/git-tainted-ctl
```

## Quick start

```sh
# 1. run the server (binds loopback; front it with your own edge/proxy)
GT_SQLITE_PATH=./git-tainted.db git-taintedd &

# 2. tell it which remote to watch
curl -fsS -X POST localhost:8080/v1/remotes -H content-type:application/json \
  -d '{"url":"https://github.com/spf13/pflag","transport":"https"}'

# 3. from inside a checkout, ask "is my tag fine?"
cd /path/to/pflag && git checkout v1.0.5
GT_SERVER=http://localhost:8080 git tainted
# → ok: v1.0.5 matches https://github.com/spf13/pflag at 2e9d26c8...
```

## CLI — `git tainted`

Run inside a working git repository:

```
git tainted [flags]
```

**Flags:**

```
--server <url>              Server base URL (repeatable; env: GT_SERVERS, GT_SERVER)
--mode <mode>               Consolidation mode: quorum|unanimous|any-bad|first (env: GT_MODE, default: quorum)
--freshness-window <dur>    Freshness window for quorum (env: GT_FRESHNESS_WINDOW_NS in ns, default: 15m)
--timeout <dur>             Per-server HTTP timeout (default: 10s)
--remote <name>             Git remote name to resolve (default: origin)
--url <url>                 Remote URL override (skips git remote get-url)
--tag <name>                Tag name override (skips git describe --exact-match HEAD)
--json                      Emit machine-readable JSON verdict to stdout
--strict                    Exit 10 instead of 0 when verdict is ok but confidence=stale
--insecure                  Allow plaintext http:// servers to non-loopback hosts (env: GT_INSECURE)
```

**What it does:**

1. Resolves the remote URL via `git remote get-url origin` (or `--remote`/`--url`).
2. Resolves the tag at HEAD via `git describe --tags --exact-match HEAD` (or `--tag`).
3. Resolves the peeled commit via `git rev-parse HEAD^{commit}`.
4. Queries all configured servers in parallel (`GET /v1/verify?remote=…&tag=…&commit=…`).
5. Consolidates the verdicts using the chosen `--mode`.
6. Prints a human verdict (JSON with `--json`) and exits with a code:

**Exit codes:**

| Code | Condition | Message |
|------|-----------|---------|
| 0 | `ok` (authoritative) | `ok: <tag> matches <remote> at <commit>` |
| 0 | `ok` (stale, without `--strict`) | `ok (stale: last sync <age> ago): ...` |
| 2 | Usage / request / parse error / all servers unreachable | stderr diagnostic |
| 3 | `mismatch` | `MISMATCH: <tag> on <remote> records <recorded-commit>, you have <commit>` |
| 4 | `tainted` | `TAINTED: <tag> on <remote> was rewritten (<reason> at <when>)` |
| 5 | `doesnt_exist` | `not found: <tag> is not a tag on <remote>` |
| 6 | `not_tracked` | `not tracked: <remote> is not registered with the server (ask an operator to add it)` |
| 7 | `no_consensus` | servers disagree and the chosen mode produced no result |
| 10 | `ok` (stale) + `--strict` | Same message as stale-ok |

## Multiple servers (quorum)

The production trust model is to run several **independent** git-tainted servers
(different operators, different networks) and let the CLI corroborate their verdicts.
No single server is a point of trust.

By default the CLI **refuses plaintext `http://` servers on non-loopback hosts** —
use `https://`, or pass `--insecure` (env `GT_INSECURE`) for local/testing. Loopback
http (e.g. `http://127.0.0.1:8080`) is always allowed without the flag.

```sh
# Query three independent servers and consolidate with the default quorum mode.
GT_SERVERS=https://tainted-a.example.com,https://tainted-b.example.com,https://tainted-c.example.com \
  git tainted

# Equivalently, with flags:
git tainted \
  --server https://tainted-a.example.com \
  --server https://tainted-b.example.com \
  --server https://tainted-c.example.com \
  --mode quorum
```

**Consolidation modes:**

| Mode | Behaviour |
|------|-----------|
| `quorum` (default) | Freshness-weighted majority of configured servers. A BAD server whose `last_synced` timestamp is newer than all GOOD servers' timestamps by more than `--freshness-window` (default 15m) overrides the majority — the clean servers are considered pre-tamper-observation. |
| `unanimous` | Every configured server must be reachable and return the same verdict. Any disagreement or unreachable server → `no_consensus` (exit 7). |
| `any-bad` | If **any** reachable server returns a BAD verdict (`tainted` or `mismatch`), that wins. Useful for maximum sensitivity. |
| `first` | In configured order, the first server returning a conclusive verdict (`ok`/`tainted`/`mismatch`) wins; falls back to the first inconclusive. |

**Freshness-weighted quorum in detail:**

The quorum algorithm recognises that a clean-majority vote can be wrong if the clean
servers simply haven't polled the remote since a tag was rewritten:

1. Among reachable servers, a **strict majority** (> half of all configured servers)
   of the same verdict normally wins.
2. **Freshness override** — if there are ≥1 BAD server and the freshest BAD
   `last_synced` is newer than the freshest GOOD `last_synced` by more than
   `--freshness-window`, the freshest BAD verdict wins. The reason line explains:
   `fresh tainted at srv-c (synced 2m ago) newer than freshest clean sync (3h ago) by 2h58m > window 15m`.
3. If no strict majority exists → `no_consensus` (exit 7).

**Human output** (three servers, freshness override active):

```
  https://a.example.com → ok (confidence=stale, last_sync=3h0m, seq=?)
  https://b.example.com → ok (confidence=stale, last_sync=3h0m, seq=?)
  https://c.example.com → tainted (confidence=authoritative, last_sync=2m0s, seq=?)
  dissent: https://a.example.com → ok (last_sync=3h0m)
  dissent: https://b.example.com → ok (last_sync=3h0m)
quorum: TAINTED — fresh tainted at https://c.example.com (synced 2m0s ago) newer than freshest clean sync (3h0m ago) by 2h58m > window 15m
```

**`--json` output** (same scenario):

```json
{
  "mode": "quorum",
  "freshness_window_ns": 900000000000,
  "final_status": "tainted",
  "exit_code": 4,
  "reason": "fresh tainted at https://c.example.com (synced 2m0s ago) ...",
  "servers": [
    {"url": "https://a.example.com", "reachable": true, "status": "ok", "confidence": "stale", "last_synced_ns": ...},
    {"url": "https://b.example.com", "reachable": true, "status": "ok", "confidence": "stale", "last_synced_ns": ...},
    {"url": "https://c.example.com", "reachable": true, "status": "tainted", "confidence": "authoritative", "last_synced_ns": ...}
  ],
  "dissent": [
    {"url": "https://a.example.com", "reachable": true, "status": "ok", ...},
    {"url": "https://b.example.com", "reachable": true, "status": "ok", ...}
  ]
}
```

> **Security note:** quorum is only meaningful if the servers are **operationally
> independent** — different operators, machines, and networks. Servers sharing
> infrastructure, credentials, or a common upstream mirror can all be compromised
> simultaneously; a quorum among them provides no additional guarantee.

## How it works

- The **server** registers remotes and polls each with `git ls-remote --tags` on a
  schedule (and on demand). Every new tag, oid change, or deletion is appended to a
  per-remote, SHA-256 hash-chained observation log — tamper-evident, since you can't
  rewrite a past row without breaking every later `row_hash`.
- **Taint** = a tag's oid changed after first observation (moved / re-tagged /
  deleted+recreated). It is **sticky** — never auto-cleared.
- **Verify** returns `ok | tainted | mismatch | doesnt_exist | not_tracked` (plus a
  freshness `confidence`), and a `ledger_proof` — the `{remote_id, seq, row_hash}` of
  the ledger row that attests the answer, so a client can independently replay and
  audit the chain.

## Honest posture

git-tainted detects oid changes observable **between polls**, per remote. It **cannot**:

- **Within-interval transient tamper** — a tag moved and restored to the same oid
  between two polls is invisible. Mitigate with shorter / jittered sync intervals.
- **Trust-on-first-observation** — the first oid recorded for a tag is taken as truth.
  A fresh server can inherit an older fleet's baseline via **seed-on-bootstrap** (below);
  ongoing corroboration is the verify CLI's query-time multi-server quorum.
- **SHA-1 probabilistic immutability** — for sha1 repos `oid = content` is probabilistic;
  prefer sha256 upstreams.

### Seed-on-bootstrap (peer seeding)

A fresh server can **bootstrap its baseline from peer git-tainted servers** instead of
starting blind — set `GT_SEED_SERVERS` and, on an empty `remotes` table, it adopts the
peers' remotes, current tag projections, and taint history under a configurable
**quorum** (`GT_SEED_QUORUM`, default 1), then rebuilds its own tamper-evident chain.
This shifts trust-on-first-observation from the new server's own `ls-remote` to the
seed peers. Honest bounds:

- **`N=1` fully trusts the single peer** — you inherit its blind spots and any pre-seed
  tamper it already trusted.
- **Quorum assumes the peers are independent.** `GT_SEED_QUORUM=N` requires ≥N listed
  peers to agree before adopting a fact, but it counts distinct **URLs**, not distinct
  operators — N colluding or sybil peers behind different names defeat it. The config
  cannot enforce independence; choose genuinely independent seeds.
- **Disagreement is a coverage-denial lever.** A tag whose peers disagree (no value
  reaches N) is **quarantined** (not adopted) — the safe choice, but a minority that
  deliberately disagrees on many tags can force them untracked. Every quarantine is
  logged per-tag with the disagreeing oids.
- **Taint adoption is quorum-gated** — a tag is seeded tainted only if ≥N peers agree
  (one malicious peer cannot inject a permanent taint).
- Seeding never weakens detection **going forward**: the rebuilt chain is tamper-evident
  and this server's own `ls-remote` syncs continue normally; a quarantined or unseeded
  tag simply reverts to trust-on-first-observation from this server's first live sync.
- **Annotated-tag fidelity gap:** the wire has no historical peeled oid, so for an
  annotated tag that already changed, the genesis observation's *historical* peeled oid
  is best-effort/empty; the **current** peeled oid (what `verify` needs) is preserved.

## API

OpenAPI 3.1 (`spec/openapi.yaml`). Remote-scoped, tags-only:

- `POST /v1/remotes`, `GET /v1/remotes`, `GET/PATCH/DELETE /v1/remotes/{id}` — register / manage remotes
- `POST /v1/remotes/{id}/sync` (202) · `GET /v1/remotes/{id}/syncs` — trigger / audit syncs
- `GET /v1/remotes/{id}/tags` · `GET /v1/remotes/{id}/tags/{name}` — tag projections (glob + RE2 search)
- `GET /v1/remotes/{id}/taint-events` · `POST /v1/remotes/{id}/taint-events/{eid}/ack` — taint log + acknowledge
- `GET /v1/verify?remote=<url|id>&tag=<name>&commit=<oid>` — the verdict (+ `ledger_proof`)
- `GET /healthz` · `/readyz` — always on; `/metrics` on a **dedicated** listener when `GT_METRICS_ADDR` is set; `/debug/pprof` only when `GT_PPROF_ENABLED=true`

The five **mutating** endpoints (create / update / delete a remote, trigger a sync,
ack a taint event) can be gated by optional **[authentication](#authentication)** —
`apikey`, `basic`, or `jwks`. Reads (verify, tags, syncs, taint-events) and the health
probes are **never** gated. By default (`GT_AUTH_MODE=none`) there is no app-level
auth — bind to loopback and front it with your own edge / proxy. The server speaks
both **HTTP/1.1 and unencrypted HTTP/2 (h2c)** on its cleartext port, so an h2c-capable
proxy can multiplex to it without TLS on the proxy↔server hop.

## Authentication

By default (`GT_AUTH_MODE=none`) the server has **no app-level auth** — it binds
loopback and trusts an edge proxy. Authentication is **opt-in** and gates only the
five **mutating** control endpoints: creating, updating, or deleting a remote,
triggering a sync, and acknowledging a taint event. Every **read** (verify, tags,
syncs, taint-events) and the health probes are **never** gated — open verification is
the whole point.

| `GT_AUTH_MODE` | Server credentials | Client sends |
|----------------|--------------------|--------------|
| `none` (default) | — | nothing |
| `apikey` | `GT_API_KEYS` (comma-separated raw keys, SHA-256-hashed at load) and/or `GT_API_KEYS_SHA256` (pre-hashed digests) | `Authorization: Bearer <key>` or `X-API-Key: <key>` |
| `basic` | `GT_BASIC_AUTH` = `user:<bcrypt-hash>[,…]` (htpasswd-style; no plaintext passwords at rest) | HTTP Basic |
| `jwks` | `GT_JWKS_URL` + `GT_JWT_ISSUER` + `GT_JWT_AUDIENCE` (+ `GT_JWT_ALGS`, default `RS256,ES256`) | `Authorization: Bearer <jwt>` |

A missing or invalid credential on a control endpoint returns `401` +
`WWW-Authenticate` before any handler runs. Keys are compared in constant time; basic
passwords are bcrypt-verified; JWTs are verified against a background-refreshed JWKS
(asymmetric algorithms only — `none` and HS\* are rejected) with issuer / audience /
expiry checks, and **fail closed** if the JWKS endpoint is unreachable.

Drive a protected server with the **`git-tainted-ctl`** admin CLI — it sends whichever
credential you give it, and reads need none:

```sh
# server with API-key auth on the control plane:
GT_AUTH_MODE=apikey GT_API_KEYS=s3cret GT_SQLITE_PATH=./git-tainted.db git-taintedd &

# register a remote — a control endpoint, so the key is required:
git-tainted-ctl --server http://localhost:8080 --api-key s3cret \
  remote add https://github.com/spf13/pflag

# list remotes — a read, so no key needed:
git-tainted-ctl --server http://localhost:8080 remote list
```

`git-tainted-ctl` also reads `GT_CTL_SERVER` and `GT_API_KEY` / `GT_TOKEN` (a JWT) /
`GT_BASIC_AUTH` from the environment.

## Configuration

Environment, prefix `GT_` (see `.env.example`). All timestamps are int64
unix-nanoseconds.

- **Storage** — `GT_DB_DRIVER` (`sqlite` default, or `mysql`), `GT_SQLITE_PATH`, `GT_MYSQL_DSN`
- **Server** — `GT_LISTEN_ADDR` (default `127.0.0.1:8080`)
- **Sync** — `GT_SYNC_CONCURRENCY`, `GT_SYNC_DEFAULT_INTERVAL_NS`, `GT_SCHEDULER_TICK_NS`, `GT_STALENESS_BUDGET_NS`
- **Git runner** — `GT_GIT_BIN`, `GT_GIT_TIMEOUT_NS`, `GT_PROTOCOL_ALLOWLIST` (`https:ssh`), `GT_HOST_ALLOWLIST`
- **Verify cache** — `GT_CACHE_ENABLED` (default `true`), `GT_CACHE_MAX_ENTRIES`, `GT_CACHE_TTL_NS`
- **Observability** — `GT_LOG_LEVEL`, `GT_METRICS_ADDR` (empty = off; set e.g. `0.0.0.0:9090` for a dedicated `/metrics` listener), `GT_PPROF_ENABLED` (default `false`)
- **Auth** — `GT_AUTH_MODE` + the per-mode credentials in [Authentication](#authentication)

Clients: `GT_SERVER` / `GT_SERVERS` (verify CLI); `GT_CTL_SERVER` + `GT_API_KEY` / `GT_TOKEN` / `GT_BASIC_AUTH` (admin CLI).

### MySQL backend

The persistence layer (`model.Store`) has **two interchangeable implementations**
behind one seam: the default SQLite store (`modernc.org/sqlite`) and a MySQL store
(`go-sql-driver/mysql`, pure-Go / CGO-free). Both pass the same Store contract; the
chain integrity, taint spine, and per-remote `chain_head` CAS behave identically.
The server runs fully without MySQL — it is opt-in.

Select it with `GT_DB_DRIVER=mysql` and a DSN in `GT_MYSQL_DSN`:

```sh
GT_DB_DRIVER=mysql \
GT_MYSQL_DSN='user:pass@tcp(127.0.0.1:3306)/git_tainted?multiStatements=true&parseTime=false&clientFoundRows=true' \
  git-taintedd
```

Required DSN params (the server validates them on startup):

- `multiStatements=true` — the schema migrations (`db/migrations-mysql/`) are
  multi-statement scripts.
- `parseTime=false` — every timestamp is a `BIGINT` unix-nanosecond value, never
  `DATETIME`.
- `clientFoundRows=true` — `UPDATE` reports matched (not changed) rows, which the
  store uses to distinguish "row not found" from "updated" (and the chain-head CAS,
  which always writes strictly-new values, is unaffected by this).

The MySQL schema targets MySQL 8 (InnoDB, `CHECK` constraints, `VARBINARY(32)` raw
oids/hashes). Migrations run automatically at startup. The MySQL integration suite
runs against a throwaway `mysql:8.4` container:

```sh
make test-mysql   # go test -tags=mysql_it ./internal/store/... (requires Docker)
```

## Develop

Go 1.26, SQLite (`modernc.org/sqlite`, pure-Go / CGO-free), sqlc, oapi-codegen,
golangci-lint v2.

```sh
make generate   # sqlc + oapi-codegen
make lint vet test race
make build      # both static CGO-free binaries → bin/
make e2e        # full register → sync → verify → tamper flow over a local git server
```

(authentication, admin CLI, verify cache).

## License

[Business Source License 1.1](LICENSE) — Licensor: Mihail Ivanov. You may use and
modify it freely and run it to monitor the integrity of git tags in your own
repositories; you may **not** offer git-tainted as a commercial hosted tag-integrity /
supply-chain service to third parties without approval. Converts to Apache License 2.0
on 2030-01-01.
