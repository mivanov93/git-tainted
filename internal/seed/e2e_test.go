//go:build e2e

package seed_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mivanov93/git-tainted/internal/api"
	"github.com/mivanov93/git-tainted/internal/auth"
	"github.com/mivanov93/git-tainted/internal/config"
	"github.com/mivanov93/git-tainted/internal/git"
	"github.com/mivanov93/git-tainted/internal/lock"
	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/seed"
	tlsync "github.com/mivanov93/git-tainted/internal/sync"
	"github.com/mivanov93/git-tainted/internal/testutil"
)

// e2eWriter routes slog output to t.Log.
type e2eWriter struct{ t *testing.T }

func (w e2eWriter) Write(p []byte) (int, error) { w.t.Logf("%s", p); return len(p), nil }

// newPeer builds a real api.Server peer over a fresh store and returns the
// httptest server + the store + a syncer (for registering and syncing a remote).
func newPeer(t *testing.T) (*httptest.Server, model.Store, *tlsync.RemoteSyncer, *testutil.FakeClock) {
	t.Helper()
	s := testutil.NewTestStore(t)
	clk := testutil.NewFakeClock(1_700_000_000_000_000_000)
	runner := git.NewRunnerWithProtocols("git", 30*time.Second, "http:https:ssh")
	syncer := tlsync.NewRemoteSyncer(s, runner, lock.NewDBLease(s, clk), clk, "seed-e2e-peer")
	handler := api.NewServer(s, clk, syncer, auth.None(), nil)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, s, syncer, clk
}

// registerAndSync inserts a remote pointing at rawURL and runs one real sync so
// the peer has a populated projection + chain.
func registerAndSync(t *testing.T, s model.Store, syncer *tlsync.RemoteSyncer, clk *testutil.FakeClock, rawURL string) model.RemoteID {
	t.Helper()
	ctx := context.Background()
	rid, err := s.CreateRemote(ctx, &model.Remote{
		URL:                 rawURL,
		NormalizedURL:       rawURL,
		Transport:           model.TransportHTTPS,
		SyncInterval:        5 * time.Minute,
		StalenessBudget:     time.Hour,
		TaintAnyTagDeletion: true,
		Status:              model.RemoteActive,
		ChainHeadHash:       make([]byte, 32),
		CreatedAtNS:         clk.NowNS(),
		UpdatedAtNS:         clk.NowNS(),
	})
	if err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}
	if _, err := syncer.SyncRemote(ctx, rid); err != nil {
		t.Fatalf("SyncRemote: %v", err)
	}
	return rid
}

func seedConfig(peers ...string) *config.Config {
	servers := ""
	for i, p := range peers {
		if i > 0 {
			servers += ","
		}
		servers += p
	}
	return &config.Config{
		SeedServers:         servers,
		SeedQuorum:          1,
		SeedConcurrency:     8,
		SeedTimeout:         10 * time.Second,
		SeedMaxRemotes:      5000,
		SeedMaxObservations: 200_000,
		SeedMaxPages:        100,
		SyncDefaultInterval: 5 * time.Minute,
		StalenessBudget:     time.Hour,
	}
}

// TestE2E_VerifyAfterSeed_AnnotatedSHA256 is the C1/C2 end-to-end guard: a seeded
// ANNOTATED sha256 tag, queried via Verify with the REAL peeled commit, must
// return `ok` (not `mismatch`). It exercises the full path: a real sha256 repo →
// a real peer sync → the Seeder over the live peer endpoint → a Verify on the
// seeded store. If C1 (copy current_peeled_oid + is_annotated) or C2 (algo
// inference) were wrong, the annotated tag would verify as `mismatch`.
func TestE2E_VerifyAfterSeed_AnnotatedSHA256(t *testing.T) {
	ctx := context.Background()
	gitSrv := testutil.StartGitServer(t)

	const base = 1_700_000_000_000_000_000
	b := testutil.NewRepo(t, gitSrv, "sha256repo.git", model.SHA256)
	peeledCommit := b.Commit("main", "c1", nil, base, base) // the commit v2.0 peels to
	b.LightweightTag("v1.0", "c1")
	b.AnnotatedTag("v2.0", "c1", "release", base+1)
	repoURL := gitSrv.URL("sha256repo.git")

	// ---- Peer: real store, synced against the repo, exposed via api.Server ----
	peerSrv, peerStore, peerSyncer, peerClk := newPeer(t)
	peerRID := registerAndSync(t, peerStore, peerSyncer, peerClk, repoURL)

	// Sanity: the peer recorded sha256 oids and the annotated tag's peeled commit.
	peerV2, err := peerStore.GetRef(ctx, peerRID, "v2.0")
	if err != nil {
		t.Fatalf("peer GetRef v2.0: %v", err)
	}
	if peerV2.CurrentOID.Algo != model.SHA256 {
		t.Fatalf("peer v2.0 not sha256 (algo=%q)", peerV2.CurrentOID.Algo)
	}
	if !peerV2.IsAnnotatedTag {
		t.Fatal("peer v2.0 must be annotated")
	}
	if peerV2.CurrentPeeledOID.Hex() != peeledCommit.Hex() {
		t.Fatalf("peer v2.0 peeled = %s, want the commit %s", peerV2.CurrentPeeledOID.Hex(), peeledCommit.Hex())
	}

	// ---- Fresh server: seed from the live peer, expose via its own api.Server --
	freshStore := testutil.NewTestStore(t)
	freshClk := testutil.NewFakeClock(base + 1_000_000)
	cfg := seedConfig(peerSrv.URL)
	seeder := seed.New(&http.Client{}, freshStore, cfg, freshClk, slog.New(slog.NewTextHandler(e2eWriter{t}, nil)))
	if err := seeder.Run(ctx); err != nil {
		t.Fatalf("seeder.Run: %v", err)
	}

	freshRID, err := freshStore.GetRemoteByURL(ctx, repoURL)
	if err != nil {
		t.Fatalf("fresh store did not adopt the remote: %v", err)
	}
	testutil.AssertChainIntact(t, ctx, freshStore, freshRID.ID)

	// The seeded annotated tag must carry the algo + is_annotated + current peeled.
	freshV2, err := freshStore.GetRef(ctx, freshRID.ID, "v2.0")
	if err != nil {
		t.Fatalf("fresh GetRef v2.0: %v", err)
	}
	if !freshV2.IsAnnotatedTag {
		t.Error("seeded v2.0 lost is_annotated (C1)")
	}
	if freshV2.CurrentPeeledOID.Hex() != peeledCommit.Hex() {
		t.Errorf("seeded v2.0 peeled = %s, want %s (C1)", freshV2.CurrentPeeledOID.Hex(), peeledCommit.Hex())
	}
	if freshV2.CurrentOID.Algo != model.SHA256 {
		t.Errorf("seeded v2.0 algo = %q, want sha256 (C2)", freshV2.CurrentOID.Algo)
	}

	// ---- Verify on the seeded store with the REAL peeled commit → ok ----------
	freshAPI := api.NewServer(freshStore, freshClk, nil, auth.None(), nil)
	freshSrv := httptest.NewServer(freshAPI)
	t.Cleanup(freshSrv.Close)

	got := verify(t, freshSrv.URL, repoURL, "v2.0", peeledCommit.Hex())
	if got.Status != "ok" {
		t.Errorf("verify seeded annotated tag with the real peeled commit: status=%q, want ok (C1 mismatch bug)", got.Status)
	}

	// A WRONG commit must still mismatch (the seeded projection is real).
	wrong := "0000000000000000000000000000000000000000000000000000000000000000"
	if got := verify(t, freshSrv.URL, repoURL, "v2.0", wrong); got.Status != "mismatch" {
		t.Errorf("verify with a wrong commit: status=%q, want mismatch", got.Status)
	}

	// The lightweight tag should also verify ok at its commit oid.
	lwV1, _ := freshStore.GetRef(ctx, freshRID.ID, "v1.0")
	if got := verify(t, freshSrv.URL, repoURL, "v1.0", lwV1.CurrentPeeledOID.Hex()); got.Status != "ok" {
		t.Errorf("verify seeded lightweight tag: status=%q, want ok", got.Status)
	}
}

// verifyResp is the subset of the verify wire shape the test inspects.
type verifyResp struct {
	Status string `json:"status"`
	Tag    string `json:"tag"`
}

func verify(t *testing.T, serverURL, remote, tag, commit string) verifyResp {
	t.Helper()
	u := fmt.Sprintf("%s/v1/verify?remote=%s&tag=%s&commit=%s", serverURL, remote, tag, commit)
	resp, err := http.Get(u) //nolint:noctx,gosec // test
	if err != nil {
		t.Fatalf("verify GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("verify HTTP %d: %s", resp.StatusCode, body)
	}
	var out verifyResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("verify decode: %v", err)
	}
	return out
}

// TestE2E_Boot_SeedsFromPeer boots the real git-taintedd binary with
// GT_SEED_SERVERS pointing at a live peer (a real api.Server synced against a
// repo) and asserts the new server comes up seeded — GET /v1/remotes shows the
// adopted remote. With GT_SEED_SERVERS unset the same fresh server starts empty.
func TestE2E_Boot_SeedsFromPeer(t *testing.T) {
	bin := buildServer(t)

	gitSrv := testutil.StartGitServer(t)
	const base = 1_700_000_000_000_000_000
	b := testutil.NewRepo(t, gitSrv, "bootrepo.git", model.SHA256)
	b.Commit("main", "c1", nil, base, base)
	b.LightweightTag("v1.0", "c1")
	repoURL := gitSrv.URL("bootrepo.git")

	peerSrv, peerStore, peerSyncer, peerClk := newPeer(t)
	registerAndSync(t, peerStore, peerSyncer, peerClk, repoURL)

	// ---- Case 1: GT_SEED_SERVERS set → fresh server boots seeded --------------
	t.Run("seeded", func(t *testing.T) {
		addr := freeAddr(t)
		dbPath := filepath.Join(t.TempDir(), "seeded.db")
		proc := startServer(t, bin, []string{
			"GT_DB_DRIVER=sqlite",
			"GT_SQLITE_PATH=" + dbPath,
			"GT_LISTEN_ADDR=" + addr,
			"GT_SEED_SERVERS=" + peerSrv.URL,
			"GT_SEED_QUORUM=1",
			"GT_SEED_INSECURE=true",              // the httptest peer is plaintext http
			"GT_SCHEDULER_TICK_NS=3600000000000", // 1h: keep the scheduler quiet during the test
		})
		defer proc.stop()
		waitHealthy(t, "http://"+addr)

		remotes := listRemotes(t, "http://"+addr)
		if len(remotes) != 1 {
			t.Logf("server logs:\n%s", proc.logs())
			t.Fatalf("seeded server should show 1 adopted remote, got %d", len(remotes))
		}
		if remotes[0].NormalizedURL != repoURL {
			t.Errorf("adopted remote = %q, want %q", remotes[0].NormalizedURL, repoURL)
		}
	})

	// ---- Case 2: GT_SEED_SERVERS unset → fresh server starts empty ------------
	t.Run("unseeded", func(t *testing.T) {
		addr := freeAddr(t)
		dbPath := filepath.Join(t.TempDir(), "empty.db")
		proc := startServer(t, bin, []string{
			"GT_DB_DRIVER=sqlite",
			"GT_SQLITE_PATH=" + dbPath,
			"GT_LISTEN_ADDR=" + addr,
			"GT_SCHEDULER_TICK_NS=3600000000000",
		})
		defer proc.stop()
		waitHealthy(t, "http://"+addr)

		if remotes := listRemotes(t, "http://"+addr); len(remotes) != 0 {
			t.Errorf("unseeded server must start empty, got %d remotes", len(remotes))
		}
	})
}

// --- boot helpers -----------------------------------------------------------

// freeAddr returns a currently-free 127.0.0.1:PORT for the subprocess to bind.
// It binds an ephemeral port, reads it, then closes the listener (a small TOCTOU
// window, but far more robust than a fixed port that a stale process can squat).
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeAddr: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func buildServer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "git-taintedd")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/mivanov93/git-tainted/cmd/git-taintedd")
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build git-taintedd: %v\n%s", err, out)
	}
	return bin
}

type serverProc struct {
	cmd *exec.Cmd
	t   *testing.T
	buf *syncBuf
}

func startServer(t *testing.T, bin string, env []string) *serverProc {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), env...)
	buf := &syncBuf{}
	cmd.Stdout = buf
	cmd.Stderr = buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	return &serverProc{cmd: cmd, t: t, buf: buf}
}

// logs dumps the captured server output to t.Log (call after an assertion fails).
func (p *serverProc) logs() string { return p.buf.String() }

func (p *serverProc) stop() {
	_ = p.cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { _ = p.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
	}
}

// syncBuf is a goroutine-safe byte buffer for capturing subprocess output.
type syncBuf struct {
	mu  sync.Mutex
	buf []byte
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

func waitHealthy(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/healthz") //nolint:noctx,gosec // test
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server at %s never became healthy", baseURL)
}

type remoteEntry struct {
	ID            int64  `json:"id"`
	NormalizedURL string `json:"normalized_url"`
}

func listRemotes(t *testing.T, baseURL string) []remoteEntry {
	t.Helper()
	resp, err := http.Get(baseURL + "/v1/remotes") //nolint:noctx,gosec // test
	if err != nil {
		t.Fatalf("list remotes: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Items []remoteEntry `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode remotes: %v", err)
	}
	return out.Items
}
