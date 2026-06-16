// Package testutil provides shared test infrastructure.
package testutil

import (
	"fmt"
	"net/http"
	"net/http/cgi" //nolint:gosec // G504: test-only, Go >=1.6.3 not vulnerable (CVE-2016-5386 fixed)
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
)

// GitServer serves one or more temp bare repos over HTTP via `git
// http-backend` (CGI). It is NOT file://: file:// ignores --filter=tree:0,
// which would mask treeless-fetch behavior under test.
type GitServer struct {
	*httptest.Server
	// Root is the directory holding served bare repos.
	Root string
}

// StartGitServer launches an http-backend-backed server rooted at a temp dir.
// Cleanup stops the server and removes the temp tree (registered on tb).
func StartGitServer(tb testing.TB) *GitServer {
	tb.Helper()
	root, err := os.MkdirTemp("", "tl-gitserver-*")
	if err != nil {
		tb.Fatalf("StartGitServer: mktemp: %v", err)
	}

	httpBackend := findGitHTTPBackend(tb)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := &cgi.Handler{
			Path: httpBackend,
			Env: []string{
				"GIT_PROJECT_ROOT=" + root,
				"GIT_HTTP_EXPORT_ALL=1",
			},
			Dir: root,
		}
		h.ServeHTTP(w, r)
	}))

	tb.Cleanup(func() {
		srv.Close()
		_ = os.RemoveAll(root)
	})
	return &GitServer{Server: srv, Root: root}
}

// URL returns the clone URL for a named repo served by this server.
func (s *GitServer) URL(repoName string) string {
	return s.Server.URL + "/" + repoName
}

// findGitHTTPBackend returns the path to git-http-backend.
func findGitHTTPBackend(tb testing.TB) string {
	tb.Helper()
	candidates := []string{
		"/usr/lib/git-core/git-http-backend",
		"/usr/libexec/git-core/git-http-backend",
		"/usr/local/lib/git-core/git-http-backend",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("git-http-backend"); err == nil {
		return p
	}
	tb.Fatal("git-http-backend not found; install git")
	return ""
}

// RepoBuilder builds a bare repo on disk under a GitServer and returns its
// clone URL. All builders use the given HashAlgo (sha1|sha256) and a fake
// clock so committer/author dates are deterministic.
type RepoBuilder struct {
	tb      testing.TB
	dir     string // working clone dir (pushes to bare repo)
	bareDir string // the bare repo dir (for git config)
	algo    model.HashAlgo
	labels  map[string]string // label → full hex oid
}

// NewRepo initializes an empty bare repo for algo and returns a builder.
// The bare repo is created inside srv.Root so it is served by the git http-backend.
func NewRepo(tb testing.TB, srv *GitServer, name string, algo model.HashAlgo) *RepoBuilder {
	tb.Helper()
	bareDir := filepath.Join(srv.Root, name)
	if err := os.MkdirAll(bareDir, 0o750); err != nil { //nolint:gosec // test fixture dir; 0o750 is safe
		tb.Fatalf("NewRepo mkdir %s: %v", bareDir, err)
	}

	// Init the bare repo (and the working clone below) with the REQUESTED object
	// format, so sha256 fixtures actually produce 32-byte/64-hex oids. Both must
	// match — a sha1 clone cannot push to a sha256 bare repo. (Previously this
	// hard-coded the sha1 default, so the algo arg only affected oid parsing and
	// the sha256 path was never exercised end-to-end.)
	if !algo.Valid() {
		tb.Fatalf("NewRepo: invalid hash algo %q (want sha1 or sha256)", algo)
	}
	objectFormat := "--object-format=" + string(algo)
	runGit(tb, bareDir, "init", "--bare", "--initial-branch=main", objectFormat)
	runGit(tb, bareDir, "config", "receive.denyCurrentBranch", "ignore")
	// Allow dumb HTTP access
	runGit(tb, bareDir, "config", "http.receivepack", "true")
	// Enable partial-clone (treeless fetch) support — required for --filter=tree:0.
	runGit(tb, bareDir, "config", "uploadpack.allowFilter", "true")
	runGit(tb, bareDir, "config", "uploadpack.allowAnySHA1InWant", "true")

	// Create a working clone to build commits in, then push to the bare repo.
	workDir, err := os.MkdirTemp("", "tl-work-*")
	if err != nil {
		tb.Fatalf("NewRepo work tmpdir: %v", err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(workDir) })

	runGit(tb, workDir, "init", "--initial-branch=main", objectFormat)
	runGit(tb, workDir, "config", "user.email", "test@example.com")
	runGit(tb, workDir, "config", "user.name", "Test")
	runGit(tb, workDir, "remote", "add", "origin", bareDir)

	return &RepoBuilder{tb: tb, dir: workDir, bareDir: bareDir, algo: algo, labels: make(map[string]string)}
}

// push pushes all branches and tags to origin (bare repo).
func (b *RepoBuilder) push() {
	b.tb.Helper()
	runGit(b.tb, b.dir, "push", "--force", "origin", "--all")
	runGit(b.tb, b.dir, "push", "--force", "origin", "--tags")
}

// parseOIDHex parses a full hex oid string into a model.OID with the builder's algo.
func (b *RepoBuilder) parseOIDHex(hexStr string) model.OID {
	b.tb.Helper()
	hexStr = strings.TrimSpace(hexStr)
	oid, err := model.ParseOID(hexStr, b.algo)
	if err != nil {
		b.tb.Fatalf("parseOIDHex %q (algo %s): %v", hexStr, b.algo, err)
	}
	return oid
}

// Commit writes one commit on branch with the given parents (by label),
// stamped at committerNS/authorNS, and returns its oid.
func (b *RepoBuilder) Commit(branch, label string, parents []string, committerNS, authorNS int64) model.OID {
	b.tb.Helper()
	return b.commitWithMessage(branch, label, parents, committerNS, authorNS, "commit "+label)
}

// commitWithMessage is the shared commit implementation; message sets the commit body.
func (b *RepoBuilder) commitWithMessage(branch, label string, parents []string, committerNS, authorNS int64, message string) model.OID {
	b.tb.Helper()
	env := gitTimeEnv(committerNS, authorNS)

	// Write a unique file so the commit always has a different tree.
	commitFile := filepath.Join(b.dir, "commit-"+label+".txt")
	content := fmt.Sprintf("label=%s committer=%d author=%d\n", label, committerNS, authorNS)
	if err := os.WriteFile(commitFile, []byte(content), 0o600); err != nil { //nolint:gosec // test fixture file; 0o600 is safe
		b.tb.Fatalf("commitWithMessage write file: %v", err)
	}

	if len(parents) == 0 {
		// Orphan (initial) commit on branch.
		runGitEnv(b.tb, b.dir, env, "checkout", "--orphan", branch)
		// Remove any staged content from a prior checkout (ignore failure if none).
		cmd := exec.Command("git", "rm", "-rf", "--cached", ".")
		cmd.Dir = b.dir
		cmd.Env = baseGitEnv()
		_ = cmd.Run() // ignore error: may fail if index is empty
	} else {
		// Make sure we're on the right branch; create it from parent if needed.
		current := currentBranchName(b.tb, b.dir)
		if current != branch {
			out, err := runGitWithOutput(b.tb, b.dir, "branch", "--list", branch)
			if err != nil || strings.TrimSpace(out) == "" {
				parentOID := b.labels[parents[0]]
				runGitEnv(b.tb, b.dir, env, "checkout", "-b", branch, parentOID)
			} else {
				runGitEnv(b.tb, b.dir, env, "checkout", branch)
			}
		}
	}

	runGitEnv(b.tb, b.dir, env, "add", ".")
	runGitEnv(b.tb, b.dir, env, "commit", "-m", message)

	hexOID := strings.TrimSpace(runGitOutput(b.tb, b.dir, "rev-parse", "HEAD"))
	b.labels[label] = hexOID
	b.push()
	return b.parseOIDHex(hexOID)
}

// LightweightTag creates a lightweight tag at the labeled commit and returns the commit oid.
// A lightweight tag OID == the commit OID it points to.
func (b *RepoBuilder) LightweightTag(name, atLabel string) model.OID {
	b.tb.Helper()
	hexOID := b.labels[atLabel]
	runGit(b.tb, b.dir, "tag", "-f", name, hexOID)
	b.push()
	// For a lightweight tag, the ref oid IS the commit oid.
	tagHex := strings.TrimSpace(runGitOutput(b.tb, b.dir, "rev-parse", name))
	return b.parseOIDHex(tagHex)
}

// AnnotatedTag creates an annotated (unsigned) tag object and returns the tag-object oid.
func (b *RepoBuilder) AnnotatedTag(name, atLabel, message string, taggerNS int64) model.OID {
	b.tb.Helper()
	hexOID := b.labels[atLabel]
	env := gitTimeEnv(taggerNS, taggerNS)
	runGitEnv(b.tb, b.dir, env, "tag", "-f", "-a", "-m", message, name, hexOID)
	b.push()
	// The tag-object oid (NOT the peeled commit).
	tagHex := strings.TrimSpace(runGitOutput(b.tb, b.dir, "rev-parse", name))
	return b.parseOIDHex(tagHex)
}

// gitTimeEnv returns env vars for deterministic git timestamps from ns values.
// Uses the @ prefix format ("@<epoch> +0000") required by git >= 2.x.
func gitTimeEnv(committerNS, authorNS int64) []string {
	committerSec := committerNS / 1_000_000_000
	authorSec := authorNS / 1_000_000_000
	return []string{
		fmt.Sprintf("GIT_COMMITTER_DATE=@%d +0000", committerSec),
		fmt.Sprintf("GIT_AUTHOR_DATE=@%d +0000", authorSec),
	}
}

// currentBranchName returns the current branch name in the working dir.
func currentBranchName(tb testing.TB, dir string) string {
	tb.Helper()
	out, _ := runGitWithOutput(tb, dir, "rev-parse", "--abbrev-ref", "HEAD")
	return strings.TrimSpace(out)
}

// baseGitEnv returns a clean base environment for git commands in fixtures.
func baseGitEnv() []string {
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

// runGit runs a git command in dir, fatal on failure.
func runGit(tb testing.TB, dir string, args ...string) {
	tb.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec // test fixture; "git" is a fixed literal
	cmd.Dir = dir
	cmd.Env = baseGitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		tb.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
}

// runGitEnv runs git with extra env vars appended to the base env.
func runGitEnv(tb testing.TB, dir string, extraEnv []string, args ...string) {
	tb.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec // test fixture; "git" is a fixed literal
	cmd.Dir = dir
	cmd.Env = append(baseGitEnv(), extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		tb.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
}

// runGitOutput runs git and returns stdout, fatal on failure.
func runGitOutput(tb testing.TB, dir string, args ...string) string {
	tb.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec // test fixture; "git" is a fixed literal
	cmd.Dir = dir
	cmd.Env = baseGitEnv()
	out, err := cmd.Output()
	if err != nil {
		tb.Fatalf("git %v in %s: %v", args, dir, err)
	}
	return string(out)
}

// runGitWithOutput runs git and returns stdout, does not fatal on failure.
func runGitWithOutput(tb testing.TB, dir string, args ...string) (string, error) {
	tb.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec // test fixture; "git" is a fixed literal
	cmd.Dir = dir
	cmd.Env = baseGitEnv()
	out, err := cmd.Output()
	return string(out), err
}
