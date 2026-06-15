package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setupFixtureRepo creates a local git repo with:
//   - one commit on main
//   - a lightweight tag "v0.1.0" at that commit
//   - an annotated tag "v1.0.0" at that commit
//   - origin remote pointing at a local bare repo path (file:// URL is used for
//     git operations but we pass it as --url to bypass URL validation which
//     rejects file:// — tests use --url with an https stub server anyway)
//
// Returns the working repo dir and the commit OID at HEAD.
func setupFixtureRepo(t *testing.T) (repoDir string, commitOID string, bareDir string) {
	t.Helper()

	// Create bare repo (the "origin").
	bare := t.TempDir()
	runFixtureGit(t, bare, "init", "--bare", "--initial-branch=main")
	runFixtureGit(t, bare, "config", "receive.denyCurrentBranch", "ignore")

	// Create working repo.
	work := t.TempDir()
	runFixtureGit(t, work, "init", "--initial-branch=main")
	runFixtureGit(t, work, "config", "user.email", "test@example.com")
	runFixtureGit(t, work, "config", "user.name", "Test")
	runFixtureGit(t, work, "remote", "add", "origin", bare)

	// Write a file and commit.
	if err := os.WriteFile(filepath.Join(work, "README"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFixtureGitEnv(t, work, []string{
		"GIT_COMMITTER_DATE=@1000000000 +0000",
		"GIT_AUTHOR_DATE=@1000000000 +0000",
	}, "add", ".")
	runFixtureGitEnv(t, work, []string{
		"GIT_COMMITTER_DATE=@1000000000 +0000",
		"GIT_AUTHOR_DATE=@1000000000 +0000",
	}, "commit", "-m", "initial commit")

	// Push.
	runFixtureGit(t, work, "push", "origin", "main")

	// Lightweight tag.
	runFixtureGit(t, work, "tag", "v0.1.0")
	// Annotated tag.
	runFixtureGitEnv(t, work, []string{
		"GIT_COMMITTER_DATE=@1000000100 +0000",
	}, "tag", "-a", "-m", "release v1.0.0", "v1.0.0")
	// Push tags.
	runFixtureGit(t, work, "push", "origin", "--tags")

	// Resolve HEAD commit.
	out := runFixtureGitOutput(t, work, "rev-parse", "HEAD^{commit}")
	commit := strings.TrimSpace(out)

	return work, commit, bare
}

// fixtureGitEnv returns a clean env for fixture git commands.
func fixtureGitEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=/tmp",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	}
}

func runFixtureGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec
	cmd.Dir = dir
	cmd.Env = fixtureGitEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func runFixtureGitEnv(t *testing.T, dir string, extra []string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec
	cmd.Dir = dir
	cmd.Env = append(fixtureGitEnv(), extra...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func runFixtureGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec
	cmd.Dir = dir
	cmd.Env = fixtureGitEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}

// ptr returns a pointer to v (generic helper).
func ptrTo[T any](v T) *T { return &v }

// cannedServer builds an httptest.Server that serves a canned verifyResponse
// for /v1/verify and returns the server URL.
func cannedServer(t *testing.T, resp verifyResponse) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/verify" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// --- Tests -------------------------------------------------------------------

// TestCLI_NotOnTag verifies exit 2 when HEAD is not at any tag.
func TestCLI_NotOnTag(t *testing.T) {
	// Build a repo without tagging HEAD.
	work := t.TempDir()
	runFixtureGit(t, work, "init", "--initial-branch=main")
	runFixtureGit(t, work, "config", "user.email", "test@example.com")
	runFixtureGit(t, work, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(work, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, work, "add", ".")
	runFixtureGitEnv(t, work, []string{
		"GIT_COMMITTER_DATE=@1000000000 +0000",
		"GIT_AUTHOR_DATE=@1000000000 +0000",
	}, "commit", "-m", "init")

	// Supply https origin so URL validation passes.
	var stdout, stderr strings.Builder
	code := runWithConfig(
		[]string{"--url", "https://github.com/example/repo.git", "--server", "http://127.0.0.1:19999"},
		nil, &stdout, &stderr,
		runConfig{repoDir: work},
	)
	if code != 2 {
		t.Fatalf("want exit 2 (not on tag), got %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "not at a tag") {
		t.Fatalf("expected 'not at a tag' message, got: %q", stderr.String())
	}
}

// TestCLI_OK verifies exit 0 for status=ok, confidence=authoritative.
func TestCLI_OK(t *testing.T) {
	repoDir, commit, _ := setupFixtureRepo(t)

	resp := verifyResponse{
		Status:     "ok",
		Confidence: "authoritative",
		Tag:        "v1.0.0",
		Remote:     &struct{ ID *int64 `json:"id,omitempty"`; NormalizedURL *string `json:"normalized_url,omitempty"` }{NormalizedURL: ptrTo("https://github.com/example/repo.git")},
	}
	srv := cannedServer(t, resp)

	var stdout, stderr strings.Builder
	code := runWithConfig(
		[]string{"--server", srv.URL, "--url", "https://github.com/example/repo.git", "--tag", "v1.0.0"},
		nil, &stdout, &stderr,
		runConfig{repoDir: repoDir},
	)
	if code != 0 {
		t.Fatalf("want exit 0, got %d; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "ok:") {
		t.Fatalf("expected 'ok:' in output, got: %q", stdout.String())
	}
	_ = commit
}

// TestCLI_OKStale verifies exit 0 for ok+stale without --strict.
func TestCLI_OKStale(t *testing.T) {
	repoDir, _, _ := setupFixtureRepo(t)

	lastSync := time.Now().Add(-2 * time.Hour).UnixNano()
	resp := verifyResponse{
		Status:       "ok",
		Confidence:   "stale",
		Tag:          "v1.0.0",
		LastSyncedNS: ptrTo(lastSync),
	}
	srv := cannedServer(t, resp)

	var stdout, stderr strings.Builder
	code := runWithConfig(
		[]string{"--server", srv.URL, "--url", "https://github.com/example/repo.git", "--tag", "v1.0.0"},
		nil, &stdout, &stderr,
		runConfig{repoDir: repoDir},
	)
	if code != 0 {
		t.Fatalf("want exit 0 (stale without --strict), got %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "stale") {
		t.Fatalf("expected 'stale' in output, got: %q", stdout.String())
	}
}

// TestCLI_OKStaleStrict verifies exit 10 for ok+stale with --strict.
func TestCLI_OKStaleStrict(t *testing.T) {
	repoDir, _, _ := setupFixtureRepo(t)

	lastSync := time.Now().Add(-2 * time.Hour).UnixNano()
	resp := verifyResponse{
		Status:       "ok",
		Confidence:   "stale",
		Tag:          "v1.0.0",
		LastSyncedNS: ptrTo(lastSync),
	}
	srv := cannedServer(t, resp)

	var stdout, stderr strings.Builder
	code := runWithConfig(
		[]string{"--server", srv.URL, "--url", "https://github.com/example/repo.git", "--tag", "v1.0.0", "--strict"},
		nil, &stdout, &stderr,
		runConfig{repoDir: repoDir},
	)
	if code != 10 {
		t.Fatalf("want exit 10 (stale + --strict), got %d; stderr=%q", code, stderr.String())
	}
}

// TestCLI_Mismatch verifies exit 3 for status=mismatch.
func TestCLI_Mismatch(t *testing.T) {
	repoDir, _, _ := setupFixtureRepo(t)

	recorded := strings.Repeat("b", 40)
	resp := verifyResponse{
		Status:     "mismatch",
		Confidence: "authoritative",
		Tag:        "v1.0.0",
		Recorded: &struct {
			RefOID          *string `json:"ref_oid,omitempty"`
			PeeledCommitOID *string `json:"peeled_commit_oid,omitempty"`
			FirstSeenNS     *int64  `json:"first_seen_ns,omitempty"`
			LastSeenNS      *int64  `json:"last_seen_ns,omitempty"`
		}{PeeledCommitOID: ptrTo(recorded)},
	}
	srv := cannedServer(t, resp)

	var stdout, stderr strings.Builder
	code := runWithConfig(
		[]string{"--server", srv.URL, "--url", "https://github.com/example/repo.git", "--tag", "v1.0.0"},
		nil, &stdout, &stderr,
		runConfig{repoDir: repoDir},
	)
	if code != 3 {
		t.Fatalf("want exit 3, got %d; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "MISMATCH") {
		t.Fatalf("expected 'MISMATCH' in output, got: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), recorded) {
		t.Fatalf("expected recorded commit %q in output, got: %q", recorded, stdout.String())
	}
}

// TestCLI_Tainted verifies exit 4 for status=tainted.
func TestCLI_Tainted(t *testing.T) {
	repoDir, _, _ := setupFixtureRepo(t)

	taintedAt := time.Now().Add(-1 * time.Hour).UnixNano()
	reason := "tag_oid_changed"
	resp := verifyResponse{
		Status:     "tainted",
		Confidence: "authoritative",
		Tag:        "v1.0.0",
		Taint: &struct {
			Reason           *string `json:"reason,omitempty"`
			FirstTaintedAtNS *int64  `json:"first_tainted_at_ns,omitempty"`
			FromOID          *string `json:"from_oid,omitempty"`
			ToOID            *string `json:"to_oid,omitempty"`
		}{Reason: &reason, FirstTaintedAtNS: &taintedAt},
	}
	srv := cannedServer(t, resp)

	var stdout, stderr strings.Builder
	code := runWithConfig(
		[]string{"--server", srv.URL, "--url", "https://github.com/example/repo.git", "--tag", "v1.0.0"},
		nil, &stdout, &stderr,
		runConfig{repoDir: repoDir},
	)
	if code != 4 {
		t.Fatalf("want exit 4, got %d; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "TAINTED") {
		t.Fatalf("expected 'TAINTED' in output, got: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "tag_oid_changed") {
		t.Fatalf("expected reason in output, got: %q", stdout.String())
	}
}

// TestCLI_DoesntExist verifies exit 5 for status=doesnt_exist.
func TestCLI_DoesntExist(t *testing.T) {
	repoDir, _, _ := setupFixtureRepo(t)

	resp := verifyResponse{
		Status:     "doesnt_exist",
		Confidence: "authoritative",
		Tag:        "v99.0.0",
	}
	srv := cannedServer(t, resp)

	var stdout, stderr strings.Builder
	code := runWithConfig(
		[]string{"--server", srv.URL, "--url", "https://github.com/example/repo.git", "--tag", "v99.0.0"},
		nil, &stdout, &stderr,
		runConfig{repoDir: repoDir},
	)
	if code != 5 {
		t.Fatalf("want exit 5, got %d; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "not found") {
		t.Fatalf("expected 'not found' in output, got: %q", stdout.String())
	}
}

// TestCLI_NotTracked verifies exit 6 for status=not_tracked.
func TestCLI_NotTracked(t *testing.T) {
	repoDir, _, _ := setupFixtureRepo(t)

	resp := verifyResponse{
		Status:     "not_tracked",
		Confidence: "authoritative",
		Tag:        "v1.0.0",
	}
	srv := cannedServer(t, resp)

	var stdout, stderr strings.Builder
	code := runWithConfig(
		[]string{"--server", srv.URL, "--url", "https://github.com/example/repo.git", "--tag", "v1.0.0"},
		nil, &stdout, &stderr,
		runConfig{repoDir: repoDir},
	)
	if code != 6 {
		t.Fatalf("want exit 6, got %d; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "not tracked") {
		t.Fatalf("expected 'not tracked' in output, got: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "operator") {
		t.Fatalf("expected operator hint in output, got: %q", stdout.String())
	}
}

// TestCLI_JSONOutput verifies --json emits parseable JSON.
func TestCLI_JSONOutput(t *testing.T) {
	repoDir, _, _ := setupFixtureRepo(t)

	resp := verifyResponse{
		Status:     "ok",
		Confidence: "authoritative",
		Tag:        "v1.0.0",
	}
	srv := cannedServer(t, resp)

	var stdout, stderr strings.Builder
	code := runWithConfig(
		[]string{"--server", srv.URL, "--url", "https://github.com/example/repo.git", "--tag", "v1.0.0", "--json"},
		nil, &stdout, &stderr,
		runConfig{repoDir: repoDir},
	)
	if code != 0 {
		t.Fatalf("want exit 0, got %d; stderr=%q", code, stderr.String())
	}
	// Verify the JSON is valid and contains expected fields.
	var got verifyResponse
	if err := json.Unmarshal([]byte(stdout.String()), &got); err != nil {
		t.Fatalf("JSON output is not parseable: %v\noutput: %q", err, stdout.String())
	}
	if got.Status != "ok" {
		t.Fatalf("JSON status: want %q, got %q", "ok", got.Status)
	}
	if got.Tag != "v1.0.0" {
		t.Fatalf("JSON tag: want %q, got %q", "v1.0.0", got.Tag)
	}
}

// TestCLI_GitResolveFromFixtureRepo verifies the CLI can resolve the tag and
// commit from an actual fixture repo (end-to-end git describe + rev-parse path).
func TestCLI_GitResolveFromFixtureRepo(t *testing.T) {
	repoDir, commit, _ := setupFixtureRepo(t)

	// Check that git describe works: HEAD is at v1.0.0 and v0.1.0.
	// After setupFixtureRepo, HEAD is still at the commit; v1.0.0 is the annotated
	// tag at that commit. git describe --tags --exact-match will return v1.0.0.
	// (If there are multiple exact tags, git picks one — we just care it works.)
	tagFromGit, err := gitDescribeTag(repoDir)
	if err != nil {
		t.Fatalf("gitDescribeTag failed: %v", err)
	}
	if tagFromGit == "" {
		t.Fatal("gitDescribeTag returned empty tag")
	}

	commitFromGit, err := gitRevParse(repoDir, "HEAD^{commit}")
	if err != nil {
		t.Fatalf("gitRevParse failed: %v", err)
	}
	if commitFromGit != commit {
		t.Fatalf("commit mismatch: gitRevParse=%q setup=%q", commitFromGit, commit)
	}

	// Now run the CLI against a canned server using the resolved tag+commit.
	resp := verifyResponse{
		Status:     "ok",
		Confidence: "authoritative",
		Tag:        tagFromGit,
	}
	srv := cannedServer(t, resp)

	var stdout, stderr strings.Builder
	// Use --url with a valid https:// URL for the validation step; the actual
	// canned server response doesn't care about the URL value.
	code := runWithConfig(
		[]string{"--server", srv.URL, "--url", "https://github.com/example/repo.git"},
		nil, &stdout, &stderr,
		runConfig{repoDir: repoDir},
	)
	if code != 0 {
		t.Fatalf("want exit 0, got %d; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

// TestCLI_BadURLRejected verifies exit 2 on bad remote URL.
func TestCLI_BadURLRejected(t *testing.T) {
	repoDir, _, _ := setupFixtureRepo(t)

	var stdout, stderr strings.Builder
	code := runWithConfig(
		[]string{"--url", "http://plaintext.example.com/repo.git", "--tag", "v1.0.0", "--server", "http://127.0.0.1:19999"},
		nil, &stdout, &stderr,
		runConfig{repoDir: repoDir},
	)
	if code != 2 {
		t.Fatalf("want exit 2 for bad URL, got %d", code)
	}
	if !strings.Contains(stderr.String(), "URL validation") {
		t.Fatalf("expected 'URL validation' in stderr, got: %q", stderr.String())
	}
}

// TestCLI_ServerEnvVar verifies GT_SERVER env is honoured.
func TestCLI_ServerEnvVar(t *testing.T) {
	repoDir, _, _ := setupFixtureRepo(t)

	resp := verifyResponse{
		Status:     "ok",
		Confidence: "authoritative",
		Tag:        "v1.0.0",
	}
	srv := cannedServer(t, resp)

	var stdout, stderr strings.Builder
	code := runWithConfig(
		[]string{"--url", "https://github.com/example/repo.git", "--tag", "v1.0.0"},
		[]string{"GT_SERVER=" + srv.URL},
		&stdout, &stderr,
		runConfig{repoDir: repoDir},
	)
	if code != 0 {
		t.Fatalf("want exit 0, got %d; stderr=%q", code, stderr.String())
	}
}
