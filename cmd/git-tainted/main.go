// Command git-tainted is the git-tainted CLI. Run inside a working git
// repository; it reads the remote URL and the current tag, calls the server's
// /v1/verify endpoint, and exits with a meaningful code.
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
//	--server <url>   Server base URL (default: $GT_SERVER or http://127.0.0.1:8080)
//	--remote <name>  Git remote name to resolve (default: origin)
//	--url <url>      Remote URL override (skips git remote get-url)
//	--tag <name>     Tag name override (skips git describe)
//	--json           Emit machine-readable JSON verdict on stdout
//	--strict         Treat stale-ok as exit 10 instead of 0
//
// Exit codes:
//
//	0   ok (authoritative), or ok (stale) without --strict
//	2   usage/request/parse error
//	3   mismatch
//	4   tainted
//	5   doesnt_exist
//	6   not_tracked
//	10  ok (stale) with --strict
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
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

// runConfig holds the injected deps for run(); the zero value uses real git.
// repoDir, when non-empty, is passed as the working directory to git commands.
type runConfig struct {
	repoDir string // overrides cwd for git shell-outs (used in tests)
}

// run is the testable entry point. Returns an OS exit code.
func run(args []string, environ []string, stdout, stderr io.Writer) int {
	return runWithConfig(args, environ, stdout, stderr, runConfig{})
}

// runWithConfig is the full entry point with injected test overrides.
func runWithConfig(args []string, environ []string, stdout, stderr io.Writer, cfg runConfig) int {
	fs := flag.NewFlagSet("git-tainted", flag.ContinueOnError)
	fs.SetOutput(stderr)

	// Define usage for --help.
	fs.Usage = func() {
		diag(stderr, `Usage: git tainted [flags]

Run inside a working git repository. Resolves the remote URL and the tag at HEAD,
calls the git-tainted server's /v1/verify endpoint, prints a verdict, and exits
with a meaningful code.

Flags:
  --server <url>   Server base URL (default: $GT_SERVER or http://127.0.0.1:8080)
  --remote <name>  Git remote name to resolve (default: origin)
  --url <url>      Remote URL override (skips git remote get-url)
  --tag <name>     Tag name override (skips git describe --exact-match HEAD)
  --json           Emit machine-readable JSON verdict to stdout
  --strict         Exit 10 instead of 0 when verdict is ok but confidence=stale

Exit codes:
  0   ok (authoritative), or ok (stale) without --strict
  2   usage / request / parse error
  3   mismatch  — tag records a different commit than you have
  4   tainted   — tag was rewritten on the remote
  5   doesnt_exist  — tag is not known on the remote
  6   not_tracked   — remote is not registered with the server
  10  ok (stale) with --strict

Limitations (§15):
  Within-interval transient tamper is invisible; trust-on-first-observation per
  remote; SHA-1 probabilistic immutability. See the server documentation.
`)
	}

	var (
		serverFlag string
		remoteFlag string
		urlFlag    string
		tagFlag    string
		jsonFlag   bool
		strictFlag bool
	)
	fs.StringVar(&serverFlag, "server", "", "Server base URL (default: $GT_SERVER or http://127.0.0.1:8080)")
	fs.StringVar(&remoteFlag, "remote", "origin", "Git remote name (default: origin)")
	fs.StringVar(&urlFlag, "url", "", "Remote URL override (skips git remote get-url)")
	fs.StringVar(&tagFlag, "tag", "", "Tag name override (skips git describe --exact-match)")
	fs.BoolVar(&jsonFlag, "json", false, "Emit machine-readable JSON verdict to stdout")
	fs.BoolVar(&strictFlag, "strict", false, "Exit 10 instead of 0 for stale-ok")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // --help exits 0
		}
		// flag.ContinueOnError: Parse already printed the error.
		return 2
	}
	if fs.NArg() > 0 {
		diagf(stderr, "error: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return 2
	}

	// Resolve server URL from flag > env > default.
	serverURL := serverFlag
	if serverURL == "" {
		serverURL = envValue(environ, "GT_SERVER")
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8080"
	}
	// Validate server URL is parseable.
	if _, err := url.Parse(serverURL); err != nil {
		diagf(stderr, "error: invalid server URL %q: %v\n", serverURL, err)
		return 2
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
	// Validate URL the same way the server does (§8 hardening).
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

	// Step 4: Call /v1/verify.
	resp, err := callVerify(serverURL, remoteURL, tagName, commit)
	if err != nil {
		diagf(stderr, "error: %v\n", err)
		return 2
	}

	// Step 5: Print verdict and return exit code.
	return verdict(resp, remoteURL, commit, jsonFlag, strictFlag, stdout, stderr)
}

// verdict prints the human (or JSON) verdict and returns the exit code.
// When jsonOut is true, only the JSON is written to stdout; the human message
// is suppressed (the exit code alone carries the verdict for scripts).
func verdict(resp *verifyResponse, remoteURL, commit string, jsonOut, strict bool, stdout, stderr io.Writer) int {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		// Return exit code only; no human message.
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

// callVerify calls GET {server}/v1/verify?remote=<url>&tag=<tag>&commit=<commit>
// and returns the parsed response.
func callVerify(serverURL, remoteURL, tagName, commit string) (*verifyResponse, error) {
	q := url.Values{}
	q.Set("remote", remoteURL)
	q.Set("tag", tagName)
	q.Set("commit", commit)
	reqURL := strings.TrimRight(serverURL, "/") + "/v1/verify?" + q.Encode()

	client := &http.Client{Timeout: 30 * time.Second}
	httpResp, err := client.Get(reqURL) //nolint:noctx // CLI: no cancellation context needed
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

// diag writes a fixed diagnostic message to w (stderr). Errors are discarded:
// a failure to write diagnostics to stderr is not actionable.
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
