// Command git-tainted is the git-tainted CLI. Run inside a working git
// repository; it reads the remote URL and the current tag, calls one or more
// git-tainted server /v1/verify endpoints, consolidates their verdicts, and
// exits with a meaningful code.
//
// Install on PATH so that "git tainted" works as a git subcommand. This binary
// has no SQLite/server dependencies — just an HTTP client and a thin git shell-out.
//
// Usage:
//
//	git tainted [flags]
//
// Flags:
//
//	--server <url>              Server base URL (repeatable; default: $GT_SERVERS or $GT_SERVER or http://127.0.0.1:8080)
//	--mode <quorum|unanimous|any-bad|first>
//	                            Consolidation mode (default: $GT_MODE or quorum)
//	--freshness-window <dur>    Duration within which sync timestamps are considered contemporaneous (default: 15m)
//	--timeout <dur>             Per-server HTTP timeout (default: 10s)
//	--remote <name>             Git remote name to resolve (default: origin)
//	--url <url>                 Remote URL override (skips git remote get-url)
//	--tag <name>                Tag name override (skips git describe)
//	--json                      Emit machine-readable JSON verdict on stdout
//	--strict                    Treat stale-ok as exit 10 instead of 0
//
// Exit codes:
//
//	0   ok (authoritative), or ok (stale) without --strict
//	2   usage/request/parse error or all servers unreachable
//	3   mismatch
//	4   tainted
//	5   doesnt_exist
//	6   not_tracked
//	7   no_consensus
//	10  ok (stale) with --strict
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mivanov93/git-tainted/internal/git"
)

func main() {
	os.Exit(run(os.Args[1:], os.Environ(), os.Stdout, os.Stderr))
}

// verifyResponse mirrors the /v1/verify JSON wire shape (oapi.VerifyResponse).
// Defined here so the CLI does not import internal/api/oapi (which pulls in
// heavy generated deps).
type verifyResponse struct {
	Status     string  `json:"status"`
	Confidence string  `json:"confidence"`
	Tag        string  `json:"tag"`
	Remote     *struct {
		ID            *int64  `json:"id,omitempty"`
		NormalizedURL *string `json:"normalized_url,omitempty"`
	} `json:"remote,omitempty"`
	Recorded *struct {
		RefOID          *string `json:"ref_oid,omitempty"`
		PeeledCommitOID *string `json:"peeled_commit_oid,omitempty"`
		FirstSeenNS     *int64  `json:"first_seen_ns,omitempty"`
		LastSeenNS      *int64  `json:"last_seen_ns,omitempty"`
	} `json:"recorded,omitempty"`
	SuppliedCommit *string `json:"supplied_commit,omitempty"`
	Taint          *struct {
		Reason           *string `json:"reason,omitempty"`
		FirstTaintedAtNS *int64  `json:"first_tainted_at_ns,omitempty"`
		FromOID          *string `json:"from_oid,omitempty"`
		ToOID            *string `json:"to_oid,omitempty"`
	} `json:"taint,omitempty"`
	LastSyncedNS *int64  `json:"last_synced_ns,omitempty"`
	SyncOutcome  *string `json:"sync_outcome,omitempty"`
}

// Mode is the consolidation mode.
type Mode string

const (
	ModeQuorum    Mode = "quorum"
	ModeUnanimous Mode = "unanimous"
	ModeAnyBad    Mode = "any-bad"
	ModeFirst     Mode = "first"
)

// ServerResult holds the outcome of querying one server.
type ServerResult struct {
	ServerURL    string
	Reachable    bool
	Status       string // "ok","tainted","mismatch","doesnt_exist","not_tracked","" if unreachable
	Confidence   string
	LastSyncedNS int64 // 0 if absent
	Err          error
	// raw response, kept for single-server passthrough
	resp *verifyResponse
}

// Consolidated is the output of consolidate().
type Consolidated struct {
	FinalStatus string // "ok","tainted","mismatch","doesnt_exist","not_tracked","no_consensus","all_unreachable"
	ExitCode    int
	Reason      string
	Dissent     []ServerResult
	PerServer   []ServerResult
	// stale is set when finalStatus==ok and at least one server says stale
	// (used for --strict logic)
	staleOK bool
}

// isBad returns true for verdict classes that indicate tamper.
func isBad(status string) bool {
	return status == "tainted" || status == "mismatch"
}

// isGood returns true for the clean verdict.
func isGood(status string) bool { return status == "ok" }

// isInconclusive returns true for verdicts that do not confirm or deny tamper.
func isInconclusive(status string) bool {
	return status == "doesnt_exist" || status == "not_tracked"
}

// badSeverity returns a severity rank for BAD verdicts: tainted > mismatch.
func badSeverity(status string) int {
	switch status {
	case "tainted":
		return 2
	case "mismatch":
		return 1
	}
	return 0
}

// runConfig holds the injected deps for run(); the zero value uses real git.
// repoDir, when non-empty, is passed as the working directory to git commands.
type runConfig struct {
	repoDir string // overrides cwd for git shell-outs (used in tests)
}

// multiStringFlag accumulates repeatable --server flags.
type multiStringFlag []string

func (m *multiStringFlag) String() string { return strings.Join(*m, ",") }
func (m *multiStringFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// run is the testable entry point. Returns an OS exit code.
func run(args []string, environ []string, stdout, stderr io.Writer) int {
	return runWithConfig(args, environ, stdout, stderr, runConfig{})
}

// runWithConfig is the full entry point with injected test overrides.
func runWithConfig(args []string, environ []string, stdout, stderr io.Writer, cfg runConfig) int {
	fs := flag.NewFlagSet("git-tainted", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.Usage = func() {
		diag(stderr, `Usage: git tainted [flags]

Run inside a working git repository. Resolves the remote URL and the tag at HEAD,
calls one or more git-tainted server /v1/verify endpoints, consolidates the verdicts,
and exits with a meaningful code.

Flags:
  --server <url>              Server base URL (repeatable; env: GT_SERVERS, GT_SERVER)
  --mode <mode>               Consolidation mode: quorum|unanimous|any-bad|first (env: GT_MODE, default: quorum)
  --freshness-window <dur>    Freshness window for quorum (env: GT_FRESHNESS_WINDOW_NS in ns, default: 15m)
  --timeout <dur>             Per-server HTTP timeout (default: 10s)
  --remote <name>             Git remote name to resolve (default: origin)
  --url <url>                 Remote URL override (skips git remote get-url)
  --tag <name>                Tag name override (skips git describe --exact-match HEAD)
  --json                      Emit machine-readable JSON verdict to stdout
  --strict                    Exit 10 instead of 0 when verdict is ok but confidence=stale

Exit codes:
  0   ok (authoritative), or ok (stale) without --strict
  2   usage / request / parse error / all servers unreachable
  3   mismatch  — tag records a different commit than you have
  4   tainted   — tag was rewritten on the remote
  5   doesnt_exist  — tag is not known on the remote
  6   not_tracked   — remote is not registered with the server
  7   no_consensus  — servers disagree and no mode produced a result
  10  ok (stale) with --strict

Multiple servers:
  Repeat --server (or set GT_SERVERS=url1,url2) to query multiple independent
  servers and consolidate with --mode (default: quorum). See README for details.

Limitations (§15):
  Within-interval transient tamper is invisible; trust-on-first-observation per
  remote; SHA-1 probabilistic immutability. See the server documentation.
`)
	}

	var (
		serverFlags        multiStringFlag
		modeFlag           string
		freshnessWindowStr string
		timeoutStr         string
		remoteFlag         string
		urlFlag            string
		tagFlag            string
		jsonFlag           bool
		strictFlag         bool
	)
	fs.Var(&serverFlags, "server", "Server base URL (repeatable)")
	fs.StringVar(&modeFlag, "mode", "", "Consolidation mode: quorum|unanimous|any-bad|first (default: quorum)")
	fs.StringVar(&freshnessWindowStr, "freshness-window", "", "Freshness window for quorum (Go duration, e.g. 15m)")
	fs.StringVar(&timeoutStr, "timeout", "10s", "Per-server HTTP timeout")
	fs.StringVar(&remoteFlag, "remote", "origin", "Git remote name (default: origin)")
	fs.StringVar(&urlFlag, "url", "", "Remote URL override (skips git remote get-url)")
	fs.StringVar(&tagFlag, "tag", "", "Tag name override (skips git describe --exact-match)")
	fs.BoolVar(&jsonFlag, "json", false, "Emit machine-readable JSON verdict to stdout")
	fs.BoolVar(&strictFlag, "strict", false, "Exit 10 instead of 0 for stale-ok")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		diagf(stderr, "error: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return 2
	}

	// --- Resolve server list ---
	servers := resolveServers([]string(serverFlags), environ)

	// --- Resolve mode ---
	mode := ModeQuorum
	if modeFlag != "" {
		mode = Mode(modeFlag)
	} else if mv := envValue(environ, "GT_MODE"); mv != "" {
		mode = Mode(mv)
	}
	switch mode {
	case ModeQuorum, ModeUnanimous, ModeAnyBad, ModeFirst:
		// valid
	default:
		diagf(stderr, "error: unknown --mode %q (want quorum|unanimous|any-bad|first)\n", mode)
		return 2
	}

	// --- Resolve freshness window ---
	freshnessWindowNS := int64(15 * time.Minute)
	if freshnessWindowStr != "" {
		d, err := time.ParseDuration(freshnessWindowStr)
		if err != nil {
			diagf(stderr, "error: invalid --freshness-window %q: %v\n", freshnessWindowStr, err)
			return 2
		}
		freshnessWindowNS = int64(d)
	} else if fwns := envValue(environ, "GT_FRESHNESS_WINDOW_NS"); fwns != "" {
		var ns int64
		if _, err := fmt.Sscanf(fwns, "%d", &ns); err != nil {
			diagf(stderr, "error: invalid GT_FRESHNESS_WINDOW_NS %q: %v\n", fwns, err)
			return 2
		}
		freshnessWindowNS = ns
	}

	// --- Resolve per-server timeout ---
	perServerTimeout := 10 * time.Second
	if timeoutStr != "" {
		d, err := time.ParseDuration(timeoutStr)
		if err != nil {
			diagf(stderr, "error: invalid --timeout %q: %v\n", timeoutStr, err)
			return 2
		}
		perServerTimeout = d
	}

	// Validate server URLs.
	for _, s := range servers {
		if _, err := url.Parse(s); err != nil {
			diagf(stderr, "error: invalid server URL %q: %v\n", s, err)
			return 2
		}
	}

	// Step 1: Resolve remote URL.
	remoteURL := urlFlag
	if remoteURL == "" {
		var err error
		remoteURL, err = gitRemoteURL(cfg.repoDir, remoteFlag)
		if err != nil {
			diagf(stderr, "error: cannot resolve remote %q: %v\n", remoteFlag, err)
			return 2
		}
	}
	if _, _, _, err := git.ValidateURL(remoteURL); err != nil {
		diagf(stderr, "error: remote URL validation failed: %v\n", err)
		return 2
	}

	// Step 2: Resolve tag.
	tagName := tagFlag
	if tagName == "" {
		var err error
		tagName, err = gitDescribeTag(cfg.repoDir)
		if err != nil {
			diag(stderr, "error: HEAD is not at a tag (use --tag to specify one)\n")
			return 2
		}
	}
	if tagName == "" {
		diag(stderr, "error: could not determine tag name\n")
		return 2
	}

	// Step 3: Resolve peeled commit.
	commit, err := gitRevParse(cfg.repoDir, "HEAD^{commit}")
	if err != nil {
		diagf(stderr, "error: cannot resolve HEAD^{commit}: %v\n", err)
		return 2
	}

	// Step 4: Fan-out — query all servers in parallel.
	results := fanOut(servers, remoteURL, tagName, commit, perServerTimeout)

	// Step 5: Single-server fast path — full backward compatibility.
	if len(servers) == 1 {
		sr := results[0]
		if !sr.Reachable {
			diagf(stderr, "error: %v\n", sr.Err)
			return 2
		}
		return verdict(sr.resp, remoteURL, commit, jsonFlag, strictFlag, stdout, stderr)
	}

	// Step 6: Multi-server consolidation.
	con := consolidate(results, mode, freshnessWindowNS)

	if jsonFlag {
		return emitMultiJSON(con, mode, freshnessWindowNS, stdout)
	}
	return emitMultiHuman(con, results, mode, strictFlag, stdout, stderr)
}

// resolveServers builds the de-duplicated ordered server list from flags + env.
func resolveServers(flagServers []string, environ []string) []string {
	var raw []string
	raw = append(raw, flagServers...)

	// GT_SERVERS (comma/space-separated list)
	if sv := envValue(environ, "GT_SERVERS"); sv != "" {
		for _, part := range strings.FieldsFunc(sv, func(r rune) bool {
			return r == ',' || r == ' '
		}) {
			if part != "" {
				raw = append(raw, part)
			}
		}
	}
	// GT_SERVER (singular legacy)
	if sv := envValue(environ, "GT_SERVER"); sv != "" {
		raw = append(raw, sv)
	}

	// De-duplicate while preserving order.
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		out = []string{"http://127.0.0.1:8080"}
	}
	return out
}

// fanOut queries all servers in parallel and returns results in the same order.
func fanOut(servers []string, remoteURL, tagName, commit string, perServerTimeout time.Duration) []ServerResult {
	results := make([]ServerResult, len(servers))
	var wg sync.WaitGroup
	wg.Add(len(servers))
	for i, srv := range servers {
		i, srv := i, srv
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), perServerTimeout)
			defer cancel()
			resp, err := callVerifyCtx(ctx, srv, remoteURL, tagName, commit)
			if err != nil {
				results[i] = ServerResult{ServerURL: srv, Reachable: false, Err: err}
				return
			}
			var lastSyncedNS int64
			if resp.LastSyncedNS != nil {
				lastSyncedNS = *resp.LastSyncedNS
			}
			results[i] = ServerResult{
				ServerURL:    srv,
				Reachable:    true,
				Status:       resp.Status,
				Confidence:   resp.Confidence,
				LastSyncedNS: lastSyncedNS,
				resp:         resp,
			}
		}()
	}
	wg.Wait()
	return results
}

// consolidate is the pure, unit-tested consolidation function.
func consolidate(results []ServerResult, mode Mode, freshnessWindowNS int64) Consolidated {
	total := len(results)

	reachable := make([]ServerResult, 0, total)
	for _, r := range results {
		if r.Reachable {
			reachable = append(reachable, r)
		}
	}

	// All unreachable.
	if len(reachable) == 0 {
		return Consolidated{
			FinalStatus: "all_unreachable",
			ExitCode:    2,
			Reason:      fmt.Sprintf("all %d servers unreachable", total),
			PerServer:   results,
		}
	}

	switch mode {
	case ModeFirst:
		return consolidateFirst(results, reachable)
	case ModeAnyBad:
		return consolidateAnyBad(results, reachable)
	case ModeUnanimous:
		return consolidateUnanimous(results, reachable, total)
	default: // quorum
		return consolidateQuorum(results, reachable, total, freshnessWindowNS)
	}
}

// consolidateQuorum implements the freshness-weighted quorum algorithm.
func consolidateQuorum(results, reachable []ServerResult, configuredTotal int, freshnessWindowNS int64) Consolidated {
	// Partition reachable by verdict class.
	var badServers, goodServers []ServerResult
	for _, r := range reachable {
		switch {
		case isBad(r.Status):
			badServers = append(badServers, r)
		case isGood(r.Status):
			goodServers = append(goodServers, r)
		}
	}

	// Freshness override: if there are BAD servers and the freshest BAD sync is
	// newer than the freshest GOOD sync by more than the window, the clean servers
	// are stale (pre-tamper observation). The BAD verdict wins regardless of count.
	if len(badServers) > 0 && len(goodServers) > 0 {
		badFreshMax := maxLastSynced(badServers)
		goodFreshMax := maxLastSynced(goodServers)
		if badFreshMax > 0 && badFreshMax > goodFreshMax+freshnessWindowNS {
			freshestBad := freshestBadServer(badServers)
			gapNS := badFreshMax - goodFreshMax
			badSyncAge := syncAgeStr(badFreshMax)
			goodSyncAge := syncAgeStr(goodFreshMax)
			reason := fmt.Sprintf(
				"fresh %s at %s (synced %s ago) newer than freshest clean sync (%s ago) by %s > window %s",
				freshestBad.Status,
				freshestBad.ServerURL,
				badSyncAge,
				goodSyncAge,
				formatDurNS(gapNS),
				formatDurNS(freshnessWindowNS),
			)
			// Dissent = good servers that lost to freshness.
			return Consolidated{
				FinalStatus: freshestBad.Status,
				ExitCode:    statusToExitCode(freshestBad.Status),
				Reason:      reason,
				Dissent:     goodServers,
				PerServer:   results,
			}
		}
	}

	// Tally verdicts to find majority (strict majority of CONFIGURED servers).
	tally := make(map[string]int, 4)
	for _, r := range reachable {
		tally[r.Status]++
	}
	majority := ""
	for status, count := range tally {
		if count*2 > configuredTotal {
			majority = status
			break
		}
	}

	if majority != "" {
		staleOK := false
		if majority == "ok" {
			for _, r := range goodServers {
				if r.Confidence == "stale" {
					staleOK = true
					break
				}
			}
		}
		// Surface any BAD dissent even when majority wins.
		var dissent []ServerResult
		if !isBad(majority) {
			dissent = append(dissent, badServers...)
		}
		if !isGood(majority) {
			dissent = append(dissent, goodServers...)
		}
		// Build reason.
		var reasonParts []string
		for status, count := range tally {
			reasonParts = append(reasonParts, fmt.Sprintf("%s×%d", status, count))
		}
		// Stable sort for deterministic output.
		sort.Strings(reasonParts)
		reason := fmt.Sprintf("majority %s (%d/%d configured; tally: %s)",
			majority, tally[majority], configuredTotal, strings.Join(reasonParts, ", "))

		return Consolidated{
			FinalStatus: majority,
			ExitCode:    statusToExitCode(majority),
			Reason:      reason,
			Dissent:     dissent,
			PerServer:   results,
			staleOK:     staleOK,
		}
	}

	// No majority → no_consensus.
	var parts []string
	for status, count := range tally {
		parts = append(parts, fmt.Sprintf("%s×%d", status, count))
	}
	sort.Strings(parts)
	reason := fmt.Sprintf("no majority among %d configured servers (tally: %s)", configuredTotal, strings.Join(parts, ", "))
	return Consolidated{
		FinalStatus: "no_consensus",
		ExitCode:    7,
		Reason:      reason,
		PerServer:   results,
	}
}

// consolidateUnanimous: all configured servers must be reachable AND agree.
func consolidateUnanimous(results, reachable []ServerResult, configuredTotal int) Consolidated {
	if len(reachable) < configuredTotal {
		unreachableCount := configuredTotal - len(reachable)
		reason := fmt.Sprintf("unanimous requires all %d servers reachable; %d unreachable", configuredTotal, unreachableCount)
		return Consolidated{
			FinalStatus: "no_consensus",
			ExitCode:    7,
			Reason:      reason,
			PerServer:   results,
		}
	}
	// All reachable — check agreement.
	verdict := reachable[0].Status
	for _, r := range reachable[1:] {
		if r.Status != verdict {
			// Disagreement — collect all as dissent.
			tally := make(map[string]int)
			for _, sr := range reachable {
				tally[sr.Status]++
			}
			var parts []string
			for status, count := range tally {
				parts = append(parts, fmt.Sprintf("%s×%d", status, count))
			}
			sort.Strings(parts)
			reason := fmt.Sprintf("servers disagree (tally: %s)", strings.Join(parts, ", "))
			return Consolidated{
				FinalStatus: "no_consensus",
				ExitCode:    7,
				Reason:      reason,
				Dissent:     reachable,
				PerServer:   results,
			}
		}
	}
	staleOK := false
	if verdict == "ok" {
		for _, r := range reachable {
			if r.Confidence == "stale" {
				staleOK = true
				break
			}
		}
	}
	return Consolidated{
		FinalStatus: verdict,
		ExitCode:    statusToExitCode(verdict),
		Reason:      fmt.Sprintf("unanimous: all %d servers agree", configuredTotal),
		PerServer:   results,
		staleOK:     staleOK,
	}
}

// consolidateAnyBad: if any reachable server says BAD, that verdict wins.
func consolidateAnyBad(results, reachable []ServerResult) Consolidated {
	// Find freshest/most-severe BAD.
	var badList []ServerResult
	for _, r := range reachable {
		if isBad(r.Status) {
			badList = append(badList, r)
		}
	}
	if len(badList) > 0 {
		best := freshestBadServer(badList)
		reason := fmt.Sprintf("any-bad: %s reported by %s", best.Status, best.ServerURL)
		return Consolidated{
			FinalStatus: best.Status,
			ExitCode:    statusToExitCode(best.Status),
			Reason:      reason,
			PerServer:   results,
		}
	}
	// No BAD — prefer ok.
	var goodList []ServerResult
	for _, r := range reachable {
		if isGood(r.Status) {
			goodList = append(goodList, r)
		}
	}
	if len(goodList) > 0 {
		staleOK := false
		for _, r := range goodList {
			if r.Confidence == "stale" {
				staleOK = true
				break
			}
		}
		return Consolidated{
			FinalStatus: "ok",
			ExitCode:    0,
			Reason:      fmt.Sprintf("any-bad: no bad verdict from %d reachable server(s)", len(reachable)),
			PerServer:   results,
			staleOK:     staleOK,
		}
	}
	// Only inconclusive.
	return consolidateMostCommonInconclusive(results, reachable)
}

// consolidateFirst: first server (in configured order) returning a conclusive
// verdict wins; if none conclusive, first inconclusive; if none reachable,
// all-unreachable is already handled by caller.
func consolidateFirst(results, reachable []ServerResult) Consolidated {
	// Scan in original order (results, not reachable, to preserve configured order).
	// First pass: conclusive (ok/tainted/mismatch).
	for _, r := range results {
		if r.Reachable && (isGood(r.Status) || isBad(r.Status)) {
			staleOK := r.Status == "ok" && r.Confidence == "stale"
			return Consolidated{
				FinalStatus: r.Status,
				ExitCode:    statusToExitCode(r.Status),
				Reason:      fmt.Sprintf("first conclusive verdict from %s", r.ServerURL),
				PerServer:   results,
				staleOK:     staleOK,
			}
		}
	}
	// Second pass: inconclusive.
	for _, r := range results {
		if r.Reachable && isInconclusive(r.Status) {
			return Consolidated{
				FinalStatus: r.Status,
				ExitCode:    statusToExitCode(r.Status),
				Reason:      fmt.Sprintf("first inconclusive verdict from %s", r.ServerURL),
				PerServer:   results,
			}
		}
	}
	// Only unreachable (shouldn't normally reach here since caller checks).
	return Consolidated{
		FinalStatus: "all_unreachable",
		ExitCode:    2,
		Reason:      fmt.Sprintf("all %d servers unreachable", len(results)),
		PerServer:   results,
	}
}

// consolidateMostCommonInconclusive picks the most common inconclusive status.
func consolidateMostCommonInconclusive(results, reachable []ServerResult) Consolidated {
	tally := make(map[string]int)
	for _, r := range reachable {
		if isInconclusive(r.Status) {
			tally[r.Status]++
		}
	}
	if len(tally) == 0 {
		return Consolidated{
			FinalStatus: "no_consensus",
			ExitCode:    7,
			Reason:      "no reachable server returned a usable verdict",
			PerServer:   results,
		}
	}
	best := ""
	for s, c := range tally {
		if best == "" || c > tally[best] {
			best = s
		}
	}
	return Consolidated{
		FinalStatus: best,
		ExitCode:    statusToExitCode(best),
		Reason:      fmt.Sprintf("most common inconclusive verdict: %s", best),
		PerServer:   results,
	}
}

// --- Output ------------------------------------------------------------------

// emitMultiHuman prints the per-server lines then the consolidated line.
func emitMultiHuman(con Consolidated, results []ServerResult, mode Mode, strict bool, stdout, stderr io.Writer) int {
	// Per-server lines.
	for _, r := range results {
		if !r.Reachable {
			outf(stdout, "  %s → UNREACHABLE (%v)\n", r.ServerURL, r.Err)
			continue
		}
		ageStr := "?"
		if r.LastSyncedNS > 0 {
			ageStr = staleDuration(&r.LastSyncedNS)
		}
		seqStr := "?"
		outf(stdout, "  %s → %s (confidence=%s, last_sync=%s, seq=%s)\n",
			r.ServerURL, r.Status, r.Confidence, ageStr, seqStr)
	}

	// Dissent lines (if any).
	for _, d := range con.Dissent {
		ageStr := "?"
		if d.LastSyncedNS > 0 {
			ageStr = staleDuration(&d.LastSyncedNS)
		}
		outf(stdout, "  dissent: %s → %s (last_sync=%s)\n", d.ServerURL, d.Status, ageStr)
	}

	// Consolidated verdict line.
	outf(stdout, "%s: %s — %s\n", mode, strings.ToUpper(con.FinalStatus), con.Reason)

	// Apply strict for stale-ok.
	if con.FinalStatus == "ok" && con.staleOK && strict {
		return 10
	}
	return con.ExitCode
}

// multiJSONOutput is the --json shape for multi-server.
type multiJSONOutput struct {
	Mode               Mode                 `json:"mode"`
	FreshnessWindowNS  int64                `json:"freshness_window_ns"`
	FinalStatus        string               `json:"final_status"`
	ExitCode           int                  `json:"exit_code"`
	Reason             string               `json:"reason"`
	Servers            []serverJSONEntry    `json:"servers"`
	Dissent            []serverJSONEntry    `json:"dissent,omitempty"`
}

type serverJSONEntry struct {
	URL          string `json:"url"`
	Reachable    bool   `json:"reachable"`
	Status       string `json:"status,omitempty"`
	Confidence   string `json:"confidence,omitempty"`
	LastSyncedNS int64  `json:"last_synced_ns,omitempty"`
	Error        string `json:"error,omitempty"`
}

func toServerJSONEntry(r ServerResult) serverJSONEntry {
	e := serverJSONEntry{
		URL:          r.ServerURL,
		Reachable:    r.Reachable,
		Status:       r.Status,
		Confidence:   r.Confidence,
		LastSyncedNS: r.LastSyncedNS,
	}
	if r.Err != nil {
		e.Error = r.Err.Error()
	}
	return e
}

func emitMultiJSON(con Consolidated, mode Mode, freshnessWindowNS int64, stdout io.Writer) int {
	servers := make([]serverJSONEntry, len(con.PerServer))
	for i, r := range con.PerServer {
		servers[i] = toServerJSONEntry(r)
	}
	dissent := make([]serverJSONEntry, len(con.Dissent))
	for i, r := range con.Dissent {
		dissent[i] = toServerJSONEntry(r)
	}
	out := multiJSONOutput{
		Mode:              mode,
		FreshnessWindowNS: freshnessWindowNS,
		FinalStatus:       con.FinalStatus,
		ExitCode:          con.ExitCode,
		Reason:            con.Reason,
		Servers:           servers,
		Dissent:           dissent,
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	return con.ExitCode
}

// --- Helpers -----------------------------------------------------------------

// statusToExitCode maps a final status string to the exit code.
func statusToExitCode(status string) int {
	switch status {
	case "ok":
		return 0
	case "mismatch":
		return 3
	case "tainted":
		return 4
	case "doesnt_exist":
		return 5
	case "not_tracked":
		return 6
	case "no_consensus":
		return 7
	default:
		return 2
	}
}

// maxLastSynced returns the maximum LastSyncedNS among the given servers.
// Returns 0 if none have a non-zero value.
func maxLastSynced(servers []ServerResult) int64 {
	var max int64
	for _, r := range servers {
		if r.LastSyncedNS > max {
			max = r.LastSyncedNS
		}
	}
	return max
}

// freshestBadServer returns the BAD server with the highest LastSyncedNS.
// Among equal timestamps, prefers higher badSeverity.
func freshestBadServer(servers []ServerResult) ServerResult {
	best := servers[0]
	for _, r := range servers[1:] {
		if r.LastSyncedNS > best.LastSyncedNS ||
			(r.LastSyncedNS == best.LastSyncedNS && badSeverity(r.Status) > badSeverity(best.Status)) {
			best = r
		}
	}
	return best
}

// syncAgeStr formats the age of a lastSyncedNS timestamp (0 = "never").
func syncAgeStr(ns int64) string {
	if ns == 0 {
		return "never"
	}
	return staleDuration(&ns)
}

// formatDurNS formats a duration in nanoseconds as a human string.
func formatDurNS(ns int64) string {
	d := time.Duration(ns)
	if d < 0 {
		d = -d
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// --- Single-server passthrough (backward compat) -----------------------------

// verdict prints the human (or JSON) verdict and returns the exit code.
// Used only for the single-server fast path.
func verdict(resp *verifyResponse, remoteURL, commit string, jsonOut, strict bool, stdout, stderr io.Writer) int {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return exitCode(resp, strict)
	}

	normalizedURL := remoteURL
	if resp.Remote != nil && resp.Remote.NormalizedURL != nil {
		normalizedURL = *resp.Remote.NormalizedURL
	}

	isStale := resp.Confidence == "stale"

	switch resp.Status {
	case "ok":
		if isStale {
			age := staleDuration(resp.LastSyncedNS)
			outln(stdout, fmt.Sprintf("ok (stale: last sync %s ago): %s matches %s at %s", age, resp.Tag, normalizedURL, commit))
			if strict {
				return 10
			}
			return 0
		}
		outf(stdout, "ok: %s matches %s at %s\n", resp.Tag, normalizedURL, commit)
		return 0

	case "mismatch":
		recorded := "<unknown>"
		if resp.Recorded != nil {
			if resp.Recorded.PeeledCommitOID != nil {
				recorded = *resp.Recorded.PeeledCommitOID
			} else if resp.Recorded.RefOID != nil {
				recorded = *resp.Recorded.RefOID
			}
		}
		outf(stdout, "MISMATCH: %s on %s records %s, you have %s\n",
			resp.Tag, normalizedURL, recorded, commit)
		return 3

	case "tainted":
		reason := "<unknown>"
		when := "<unknown>"
		if resp.Taint != nil {
			if resp.Taint.Reason != nil {
				reason = *resp.Taint.Reason
			}
			if resp.Taint.FirstTaintedAtNS != nil {
				when = time.Unix(0, *resp.Taint.FirstTaintedAtNS).UTC().Format(time.RFC3339)
			}
		}
		outf(stdout, "TAINTED: %s on %s was rewritten (%s at %s)\n",
			resp.Tag, normalizedURL, reason, when)
		return 4

	case "doesnt_exist":
		outf(stdout, "not found: %s is not a tag on %s\n", resp.Tag, normalizedURL)
		return 5

	case "not_tracked":
		outf(stdout, "not tracked: %s is not registered with the server (ask an operator to add it)\n", normalizedURL)
		return 6

	default:
		diagf(stderr, "error: unexpected status %q from server\n", resp.Status)
		return 2
	}
}

// exitCode returns the numeric exit code for a response (used by --json path).
func exitCode(resp *verifyResponse, strict bool) int {
	switch resp.Status {
	case "ok":
		if strict && resp.Confidence == "stale" {
			return 10
		}
		return 0
	case "mismatch":
		return 3
	case "tainted":
		return 4
	case "doesnt_exist":
		return 5
	case "not_tracked":
		return 6
	default:
		return 2
	}
}

// staleDuration formats the age of the last sync as a human-friendly string.
func staleDuration(lastSyncedNS *int64) string {
	if lastSyncedNS == nil || *lastSyncedNS == 0 {
		return "never"
	}
	d := time.Since(time.Unix(0, *lastSyncedNS))
	if d < 0 {
		d = 0
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// callVerifyCtx calls /v1/verify with a context (used by fan-out).
func callVerifyCtx(ctx context.Context, serverURL, remoteURL, tagName, commit string) (*verifyResponse, error) {
	q := url.Values{}
	q.Set("remote", remoteURL)
	q.Set("tag", tagName)
	q.Set("commit", commit)
	reqURL := strings.TrimRight(serverURL, "/") + "/v1/verify?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	client := &http.Client{}
	httpResp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling server: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode == http.StatusUnprocessableEntity {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(httpResp.Body).Decode(&errBody)
		if errBody.Error != "" {
			return nil, fmt.Errorf("server rejected request (422): %s", errBody.Error)
		}
		return nil, fmt.Errorf("server returned 422")
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d", httpResp.StatusCode)
	}

	var resp verifyResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	if resp.Status == "" {
		return nil, fmt.Errorf("response missing status field")
	}
	return &resp, nil
}

// gitRemoteURL runs `git remote get-url <name>` (in dir, or cwd if dir=="").
func gitRemoteURL(dir, remoteName string) (string, error) {
	out, err := runGitIn(dir, "remote", "get-url", remoteName)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// gitDescribeTag runs `git describe --tags --exact-match HEAD` and returns the
// tag name. Returns an error if HEAD is not at an exact tag.
func gitDescribeTag(dir string) (string, error) {
	out, err := runGitIn(dir, "describe", "--tags", "--exact-match", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// gitRevParse runs `git rev-parse <ref>` and returns the oid.
func gitRevParse(dir, ref string) (string, error) {
	out, err := runGitIn(dir, "rev-parse", ref)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// runGitIn execs git with the given subcommand args in dir (or cwd if dir=="").
func runGitIn(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...) //nolint:gosec // G204: fixed literal "git", args are controlled
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	return out, nil
}

// envValue returns the value of the named env var from an environ slice.
func envValue(environ []string, key string) string {
	prefix := key + "="
	for _, e := range environ {
		if strings.HasPrefix(e, prefix) {
			return e[len(prefix):]
		}
	}
	return ""
}

// diag writes a fixed diagnostic message to w (stderr).
func diag(w io.Writer, msg string) {
	_, _ = io.WriteString(w, msg)
}

// diagf formats and writes a diagnostic message to w (stderr).
func diagf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// outf formats and writes a verdict line to w (stdout).
func outf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// outln writes a verdict line (with newline) to w (stdout).
func outln(w io.Writer, msg string) {
	_, _ = fmt.Fprintln(w, msg)
}
