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

## Two binaries

| Binary | Purpose |
|--------|---------|
| `git-taintedd` | Server — polls remotes, maintains the tamper-evident ledger, serves the API |
| `git-tainted` | CLI — run inside a working repo; exits with a meaningful code |

`git-tainted` is named so that `git tainted` works as a git subcommand when it is on
your `PATH`.

## Install

```sh
# CLI — becomes `git tainted` once on your PATH
go install github.com/mivanov93/git-tainted/cmd/git-tainted@latest

# Server
go install github.com/mivanov93/git-tainted/cmd/git-taintedd@latest
# or from a clone:  make build   →   bin/git-taintedd, bin/git-tainted
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
--server <url>   Server base URL (default: $GT_SERVER or http://127.0.0.1:8080)
--remote <name>  Git remote name to resolve (default: origin)
--url <url>      Remote URL override (skips git remote get-url)
--tag <name>     Tag name override (skips git describe --exact-match HEAD)
--json           Emit machine-readable JSON verdict to stdout
--strict         Exit 10 instead of 0 when verdict is ok but confidence=stale
```

**What it does:**

1. Resolves the remote URL via `git remote get-url origin` (or `--remote`/`--url`).
2. Resolves the tag at HEAD via `git describe --tags --exact-match HEAD` (or `--tag`).
3. Resolves the peeled commit via `git rev-parse HEAD^{commit}`.
4. Calls `GET {server}/v1/verify?remote=<url>&tag=<tag>&commit=<commit>`.
5. Prints a human verdict (JSON with `--json`) and exits with a code:

**Exit codes:**

| Code | Condition | Message |
|------|-----------|---------|
| 0 | `ok` (authoritative) | `ok: <tag> matches <remote> at <commit>` |
| 0 | `ok` (stale, without `--strict`) | `ok (stale: last sync <age> ago): ...` |
| 2 | Usage / request / parse error | stderr diagnostic |
| 3 | `mismatch` | `MISMATCH: <tag> on <remote> records <recorded-commit>, you have <commit>` |
| 4 | `tainted` | `TAINTED: <tag> on <remote> was rewritten (<reason> at <when>)` |
| 5 | `doesnt_exist` | `not found: <tag> is not a tag on <remote>` |
| 6 | `not_tracked` | `not tracked: <remote> is not registered with the server (ask an operator to add it)` |
| 10 | `ok` (stale) + `--strict` | Same message as stale-ok |

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
- **Trust-on-first-observation** — the first oid recorded for a tag is taken as truth;
  there is no cross-remote corroboration.
- **SHA-1 probabilistic immutability** — for sha1 repos `oid = content` is probabilistic;
  prefer sha256 upstreams.

## API

OpenAPI 3.1 (`spec/openapi.yaml`). Remote-scoped, tags-only:

- `POST /v1/remotes`, `GET /v1/remotes`, `GET/PATCH/DELETE /v1/remotes/{id}` — register / manage remotes
- `POST /v1/remotes/{id}/sync` (202) · `GET /v1/remotes/{id}/syncs` — trigger / audit syncs
- `GET /v1/remotes/{id}/tags` · `GET /v1/remotes/{id}/tags/{name}` — tag projections (glob + RE2 search)
- `GET /v1/remotes/{id}/taint-events` · `POST /v1/remotes/{id}/taint-events/{eid}/ack` — taint log + acknowledge
- `GET /v1/verify?remote=<url|id>&tag=<name>&commit=<oid>` — the verdict (+ `ledger_proof`)
- `GET /healthz` · `/readyz` · `/metrics` · `/debug/pprof`

There is **no app-level auth** — bind to loopback and front it with your own edge / proxy.

## Configuration

Environment, prefix `GT_` (see `.env.example`): `GT_SQLITE_PATH`, `GT_LISTEN_ADDR`
(default `127.0.0.1:8080`), `GT_SYNC_DEFAULT_INTERVAL_NS`, `GT_SCHEDULER_TICK_NS`,
`GT_STALENESS_BUDGET_NS`, `GT_PROTOCOL_ALLOWLIST` (`https:ssh`), `GT_GIT_BIN`,
`GT_GIT_TIMEOUT_NS`, `GT_METRICS_ADDR`. CLI: `GT_SERVER`. All timestamps are int64
unix-nanoseconds.

## Develop

Go 1.26, SQLite (`modernc.org/sqlite`, pure-Go / CGO-free), sqlc, oapi-codegen,
golangci-lint v2.

```sh
make generate   # sqlc + oapi-codegen
make lint vet test race
make build      # both static CGO-free binaries → bin/
make e2e        # full register → sync → verify → tamper flow over a local git server
```

Design: [`docs/superpowers/specs/2026-06-14-git-tainted-design.md`](docs/superpowers/specs/2026-06-14-git-tainted-design.md).

## License

[Business Source License 1.1](LICENSE) — Licensor: Mihail Ivanov. You may use and
modify it freely and run it to monitor the integrity of git tags in your own
repositories; you may **not** offer git-tainted as a commercial hosted tag-integrity /
supply-chain service to third parties without approval. Converts to Apache License 2.0
on 2030-01-01.
