# Security Policy

`git-tainted` is a tamper-evidence tool for Git tags: it records the commit a tag
points at the first time it observes it and maintains a per-remote, SHA-256
hash-chained ledger, so any later mutation, deletion, or re-creation of that tag
is detectable. Because it is itself a security tool, reports are taken seriously
and handled quickly.

## Reporting a Vulnerability

**Please do not open a public issue, pull request, or discussion for a suspected
vulnerability.** Disclosing before a fix exists puts every user at risk.

Report privately through **GitHub Private Vulnerability Reporting**:

> Repository → **Security** tab → **Report a vulnerability**

This keeps the report, the discussion, and the fix private until coordinated
disclosure. (If the button is missing, private reporting has not been enabled
yet — see *For maintainers* at the bottom.)

Please include, if possible:

- the affected component — `git-taintedd` (server), `git-tainted` /
  `git-tainted-ctl` (CLIs), the chain/verify logic, auth, or seed bootstrap —
  and the version or commit;
- a minimal reproduction or proof of concept;
- the impact you believe it has (what an attacker gains);
- any suggested remediation.

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | within 3 business days |
| Initial assessment + severity | within 7 business days |
| Fix or mitigation for confirmed high/critical issues | as fast as practical, with progress updates |

Disclosure is coordinated: we agree a date with you (default **90 days** from the
report, or sooner once a fix ships), credit you in the advisory and release notes
unless you prefer to stay anonymous, and request a CVE where warranted.

## Supported Versions

`git-tainted` has not yet cut a stable (`v1.0.0`) release; it is pre-1.0 and the
API/CLI surface may still change.

| Version | Supported |
| --- | --- |
| `master` (latest commit) | ✅ — fixes land here first |
| Most recent tagged release | ✅ |
| Anything older | ❌ — upgrade to the latest |

Once a `v1.x` line exists, this table will track the supported minor lines.

## Scope

**In scope** — anything that defeats the tool's purpose or its controls, e.g.:

- making a tampered, deleted, or re-created tag **verify as clean**, forging a
  `ledger_proof`, or breaking the ledger's append-only / hash-chain property;
- **bypassing authentication** on the mutating control endpoints
  (`GT_AUTH_MODE=apikey|basic|jwks`), including JWT `alg`-confusion or forgery;
- injection (SQL, command, header), or SSRF/abuse via the `git ls-remote`
  subprocess and the remote URL it is given;
- the **seed bootstrap** adopting attacker-controlled state past its quorum and
  continuity checks;
- leaking secrets (API keys, tokens, DB DSNs) into logs, errors, or responses.

**Out of scope** — documented design boundaries and operator responsibilities:

- **Trust-on-first-observation.** If a tag was already tampered *before*
  git-tainted first observed it, the tool cannot know. This is a stated
  limitation, not a vulnerability.
- **Quorum independence.** Cross-server quorum during seeding is only as strong
  as the operational independence of the peers (see the README security note).
- **Intentional escape hatches / misconfiguration**, e.g. running
  `GT_AUTH_MODE=none` on an untrusted network, or `--insecure` / `GT_INSECURE`
  plaintext transport — both are opt-in and documented.
- **Unauthenticated read load.** Read/verify endpoints are open by design;
  capacity and rate-limiting are deployment concerns.
- **Third-party dependency vulnerabilities** — report those upstream. We track
  and patch them via `govulncheck` and Renovate; if a dependency flaw is
  exploitable *specifically through* git-tainted, do report it here.

## Security posture

- Per-remote **SHA-256 hash-chained** observation ledger — tamper-*evidence*, not
  prevention; `verify` returns a closed verdict set plus a `ledger_proof`.
- **Opt-in authentication** on mutating endpoints (API key / Basic / JWKS), with
  fail-closed JWT validation hardened against `alg` confusion.
- Plaintext transport to non-loopback hosts is **refused** unless explicitly
  overridden.
- Supply chain: CI runs `govulncheck` and `gosec`; release images are
  **cosign-signed** with SBOM + provenance attestations.

## For maintainers

To enable the private reporting channel above:
**Settings → Code security and analysis → Private vulnerability reporting →
Enable** (labelled *Advanced Security* in some orgs). Optionally add a dedicated
security contact (e.g. `security@<domain>`) if you want an email fallback to the
GitHub advisory flow.
