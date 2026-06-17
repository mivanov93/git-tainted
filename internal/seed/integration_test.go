package seed

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mivanov93/git-tainted/internal/config"
	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/testutil"
)

// --- stub peer --------------------------------------------------------------

// stubPeer is a minimal git-tainted peer over httptest: it serves canned
// remotes / tags / taint-events JSON with a working (single-page) pagination
// contract (next_cursor=0 ⇒ no more). It exercises the real peerClient + Seeder
// fetch path without needing a full api.Server.
type stubPeer struct {
	remotes map[int64]wireRemote       // remoteID → remote
	tags    map[int64][]wireTag        // remoteID → tags
	events  map[int64][]wireTaintEvent // remoteID → taint events
}

func newStubPeer() *stubPeer {
	return &stubPeer{
		remotes: map[int64]wireRemote{},
		tags:    map[int64][]wireTag{},
		events:  map[int64][]wireTaintEvent{},
	}
}

// addRemote registers a remote with its tags/events on the stub.
func (p *stubPeer) addRemote(id int64, normURL string, tags []wireTag, events []wireTaintEvent) {
	p.remotes[id] = wireRemote{
		ID: id, URL: normURL, NormalizedURL: normURL,
		Transport: "https", TaintAnyTagDeletion: true,
	}
	p.tags[id] = tags
	p.events[id] = events
}

func (p *stubPeer) start(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/remotes", func(w http.ResponseWriter, r *http.Request) {
		// cursor>0 ⇒ second page ⇒ empty (single-page stub).
		if r.URL.Query().Get("cursor") != "0" && r.URL.Query().Get("cursor") != "" {
			writeJSON(w, wireRemoteList{Items: []wireRemote{}, NextCursor: ip(0)})
			return
		}
		items := make([]wireRemote, 0, len(p.remotes))
		for _, rm := range p.remotes {
			items = append(items, rm)
		}
		writeJSON(w, wireRemoteList{Items: items, NextCursor: ip(0)})
	})
	mux.HandleFunc("/v1/remotes/", func(w http.ResponseWriter, r *http.Request) {
		// Paths: /v1/remotes/{id}/tags  or  /v1/remotes/{id}/taint-events
		rest := strings.TrimPrefix(r.URL.Path, "/v1/remotes/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		id := atoi64(parts[0])
		secondPage := r.URL.Query().Get("cursor") != "0" && r.URL.Query().Get("cursor") != ""
		switch parts[1] {
		case "tags":
			if secondPage {
				writeJSON(w, wireTagList{Items: []wireTag{}, NextCursor: ip(0)})
				return
			}
			writeJSON(w, wireTagList{Items: p.tags[id], NextCursor: ip(0)})
		case "taint-events":
			if secondPage {
				writeJSON(w, wireTaintEventList{Items: []wireTaintEvent{}, NextCursor: ip(0)})
				return
			}
			writeJSON(w, wireTaintEventList{Items: p.events[id], NextCursor: ip(0)})
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func atoi64(s string) int64 {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

// --- integration seeder over stub peers -------------------------------------

// runSeeder builds a Seeder over a fresh store pointed at the given peer URLs
// with the given quorum/allowlist, runs it, and returns the store.
func runSeeder(t *testing.T, peers []string, quorum int, allowlist string) model.Store {
	t.Helper()
	store := testutil.NewTestStore(t)
	cfg := &config.Config{
		SeedServers:         strings.Join(peers, ","),
		SeedQuorum:          quorum,
		SeedRemotes:         allowlist,
		SeedConcurrency:     8,
		SeedTimeout:         5 * time.Second,
		SeedMaxRemotes:      5000,
		SeedMaxObservations: 200_000,
		SeedMaxPages:        100,
		SyncDefaultInterval: 5 * time.Minute,
		StalenessBudget:     time.Hour,
	}
	clk := testutil.NewFakeClock(1_700_000_000_000_000_000)
	s := New(&http.Client{}, store, cfg, clk, slog.New(slog.NewTextHandler(testWriter{t}, nil)))
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("seeder.Run: %v", err)
	}
	return store
}

// --- happy path -------------------------------------------------------------

func TestIntegration_HappyPath_N2(t *testing.T) {
	const url = "https://example.com/owner/repo"
	mk := func() *httptest.Server {
		p := newStubPeer()
		p.addRemote(1, url, []wireTag{tag(7, "v1", oidA, oidA)}, nil)
		return p.start(t)
	}
	p1, p2 := mk(), mk()
	store := runSeeder(t, []string{p1.URL, p2.URL}, 2, "")

	ctx := context.Background()
	r, err := store.GetRemoteByURL(ctx, url)
	if err != nil {
		t.Fatalf("adopted remote missing: %v", err)
	}
	testutil.AssertChainIntact(t, ctx, store, r.ID)
	ref, err := store.GetRef(ctx, r.ID, "v1")
	if err != nil {
		t.Fatalf("adopted tag missing: %v", err)
	}
	if ref.FirstOID.Hex() != oidA {
		t.Errorf("first_oid = %s, want %s", ref.FirstOID.Hex(), oidA)
	}
	if ref.Tainted {
		t.Error("clean tag must not be tainted")
	}
}

// --- poisoned peer quarantined under N=2 ------------------------------------

func TestIntegration_PoisonedPeer_QuarantinedN2(t *testing.T) {
	const url = "https://example.com/owner/repo"
	good := func() *httptest.Server {
		p := newStubPeer()
		p.addRemote(1, url, []wireTag{tag(7, "v1", oidA, oidA)}, nil)
		return p.start(t)
	}
	// Poisoned peer reports a DIFFERENT first_oid for v1.
	poison := newStubPeer()
	poison.addRemote(1, url, []wireTag{tag(7, "v1", oidB, oidB)}, nil)

	g1, g2, bad := good(), good(), poison.start(t)
	// 3 peers, N=2: remote adopted (3 report it); v1 has A×2, B×1 → A wins quorum.
	store := runSeeder(t, []string{g1.URL, g2.URL, bad.URL}, 2, "")

	ctx := context.Background()
	r, _ := store.GetRemoteByURL(ctx, url)
	ref, err := store.GetRef(ctx, r.ID, "v1")
	if err != nil {
		t.Fatalf("v1 should be adopted at the quorum oid A: %v", err)
	}
	if ref.FirstOID.Hex() != oidA {
		t.Errorf("first_oid = %s, want the quorum value %s (poison must lose)", ref.FirstOID.Hex(), oidA)
	}
}

func TestIntegration_TwoPeersDisagree_TagQuarantined(t *testing.T) {
	const url = "https://example.com/owner/repo"
	p1 := newStubPeer()
	p1.addRemote(1, url, []wireTag{tag(7, "v1", oidA, oidA)}, nil)
	p2 := newStubPeer()
	p2.addRemote(1, url, []wireTag{tag(7, "v1", oidB, oidB)}, nil)
	s1, s2 := p1.start(t), p2.start(t)

	// N=2, only 2 peers disagreeing on v1's first_oid → v1 quarantined; remote
	// itself still adopted (2 peers report it) but with no tags.
	store := runSeeder(t, []string{s1.URL, s2.URL}, 2, "")
	ctx := context.Background()
	r, err := store.GetRemoteByURL(ctx, url)
	if err != nil {
		t.Fatalf("remote should be adopted (2 peers report it): %v", err)
	}
	if _, err := store.GetRef(ctx, r.ID, "v1"); err == nil {
		t.Error("v1 must be quarantined (peers disagree, no quorum)")
	}
	testutil.AssertChainIntact(t, ctx, store, r.ID) // vacuous (no tags) but must hold
}

// --- fabricated taint not adopted under N=2 (M1) ----------------------------

func TestIntegration_FabricatedTaint_NotAdoptedN2(t *testing.T) {
	const url = "https://example.com/owner/repo"
	clean := func() *httptest.Server {
		p := newStubPeer()
		p.addRemote(1, url, []wireTag{tag(7, "v1", oidA, oidA)}, nil)
		return p.start(t)
	}
	// Poison peer claims v1 is tainted A→C with a fabricated event.
	poison := newStubPeer()
	ptag := tag(7, "v1", oidA, oidC)
	ptag.Tainted = true
	ptag.TaintFirstNS = ip(9000)
	pev := wireTaintEvent{ID: 1, RemoteID: 1, RefID: 7, Reason: "tag_oid_changed", FromOID: sp(oidA), ToOID: sp(oidC), DetectedAtNS: 9000}
	poison.addRemote(1, url, []wireTag{ptag}, []wireTaintEvent{pev})

	c1, c2, bad := clean(), clean(), poison.start(t)
	store := runSeeder(t, []string{c1.URL, c2.URL, bad.URL}, 2, "")

	ctx := context.Background()
	r, _ := store.GetRemoteByURL(ctx, url)
	ref, err := store.GetRef(ctx, r.ID, "v1")
	if err != nil {
		t.Fatalf("v1 should be adopted clean: %v", err)
	}
	if ref.Tainted {
		t.Error("sub-quorum fabricated taint must NOT be adopted (M1)")
	}
	// No taint_events row should have been written.
	evs, _, err := store.ListTaintEvents(ctx, r.ID, 100, 0)
	if err != nil {
		t.Fatalf("ListTaintEvents: %v", err)
	}
	if len(evs) != 0 {
		t.Errorf("want 0 taint events, got %d (fabricated taint leaked)", len(evs))
	}
	testutil.AssertChainIntact(t, ctx, store, r.ID)
}

// --- peer down (partial failure) --------------------------------------------

func TestIntegration_PeerDown_N1_StillSeeds(t *testing.T) {
	const url = "https://example.com/owner/repo"
	up := newStubPeer()
	up.addRemote(1, url, []wireTag{tag(7, "v1", oidA, oidA)}, nil)
	upSrv := up.start(t)

	// A dead peer URL (closed server) plus one live peer. N=1 → the live peer seeds.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close() // make it unreachable

	store := runSeeder(t, []string{deadURL, upSrv.URL}, 1, "")
	ctx := context.Background()
	if _, err := store.GetRemoteByURL(ctx, url); err != nil {
		t.Fatalf("the live peer's remote should be seeded despite the dead peer: %v", err)
	}
}

func TestIntegration_AllPeersDown_StartsEmpty(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	store := runSeeder(t, []string{deadURL}, 1, "")
	n, err := store.CountAllRemotes(context.Background())
	if err != nil {
		t.Fatalf("CountAllRemotes: %v", err)
	}
	if n != 0 {
		t.Errorf("no peer reachable → store must be empty, got %d remotes", n)
	}
}

// --- allowlist --------------------------------------------------------------

func TestIntegration_Allowlist_FiltersRemotes(t *testing.T) {
	const keep = "https://github.com/org/keep"
	const drop = "https://github.com/other/drop"
	mk := func() *httptest.Server {
		p := newStubPeer()
		p.addRemote(1, keep, []wireTag{tag(7, "v1", oidA, oidA)}, nil)
		p.addRemote(2, drop, []wireTag{tag(8, "v1", oidB, oidB)}, nil)
		return p.start(t)
	}
	p1, p2 := mk(), mk()
	store := runSeeder(t, []string{p1.URL, p2.URL}, 2, "https://github.com/org/*")

	ctx := context.Background()
	if _, err := store.GetRemoteByURL(ctx, keep); err != nil {
		t.Errorf("allowed remote should be adopted: %v", err)
	}
	if _, err := store.GetRemoteByURL(ctx, drop); err == nil {
		t.Error("filtered remote must NOT be adopted")
	}
}

// --- empty-DB guard no-op on re-run -----------------------------------------

func TestIntegration_ReRun_NoOpWhenNotEmpty(t *testing.T) {
	const url = "https://example.com/owner/repo"
	mk := func() *httptest.Server {
		p := newStubPeer()
		p.addRemote(1, url, []wireTag{tag(7, "v1", oidA, oidA)}, nil)
		return p.start(t)
	}
	p1, p2 := mk(), mk()
	cfg := &config.Config{
		SeedServers:         p1.URL + "," + p2.URL,
		SeedQuorum:          2,
		SeedConcurrency:     8,
		SeedTimeout:         5 * time.Second,
		SeedMaxRemotes:      5000,
		SeedMaxObservations: 200_000,
		SeedMaxPages:        100,
		SyncDefaultInterval: 5 * time.Minute,
		StalenessBudget:     time.Hour,
	}
	store := testutil.NewTestStore(t)
	clk := testutil.NewFakeClock(1_700_000_000_000_000_000)
	s := New(&http.Client{}, store, cfg, clk, slog.New(slog.NewTextHandler(testWriter{t}, nil)))

	ctx := context.Background()
	if err := s.Run(ctx); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	r, err := store.GetRemoteByURL(ctx, url)
	if err != nil {
		t.Fatalf("first Run should have seeded: %v", err)
	}
	_, lenBefore, _ := store.GetChainHead(ctx, r.ID)

	// Second Run: the store is non-empty → must be a NO-OP (no duplicate writes).
	if err := s.Run(ctx); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	n, _ := store.CountAllRemotes(ctx)
	if n != 1 {
		t.Errorf("re-run must not add remotes; count = %d, want 1", n)
	}
	_, lenAfter, _ := store.GetChainHead(ctx, r.ID)
	if lenAfter != lenBefore {
		t.Errorf("re-run must not append observations; chain_len %d → %d", lenBefore, lenAfter)
	}
}

// --- disabled feature is a no-op --------------------------------------------

func TestIntegration_Disabled_NoOp(t *testing.T) {
	store := testutil.NewTestStore(t)
	cfg := &config.Config{ // SeedServers empty ⇒ disabled
		SeedQuorum: 1, SeedConcurrency: 8, SeedTimeout: time.Second,
		SeedMaxRemotes: 1, SeedMaxObservations: 1, SeedMaxPages: 1,
	}
	clk := testutil.NewFakeClock(1)
	s := New(&http.Client{}, store, cfg, clk, slog.New(slog.NewTextHandler(testWriter{t}, nil)))
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("disabled Run should be a clean no-op: %v", err)
	}
	n, _ := store.CountAllRemotes(context.Background())
	if n != 0 {
		t.Errorf("disabled seeder must write nothing, got %d remotes", n)
	}
}
