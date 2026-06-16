package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Multi-server helpers ---------------------------------------------------

// cannedServerWithSync builds an httptest.Server serving a verifyResponse that
// includes a last_synced_ns value.
func cannedServerWithSync(t *testing.T, resp verifyResponse) *httptest.Server {
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

// unavailableServer returns a server that immediately closes the connection.
func unavailableServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// force a non-200 to simulate unreachable
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runMulti is a convenience wrapper for runWithConfig with a minimal git-free setup.
// It sets --url and --tag directly to bypass git resolution.
func runMulti(t *testing.T, extraArgs []string, environ []string) (stdout, stderr string, code int) {
	t.Helper()
	repoDir, _, _ := setupFixtureRepo(t)
	var sb, eb strings.Builder
	allArgs := append([]string{
		"--url", "https://github.com/example/repo.git",
		"--tag", "v1.0.0",
	}, extraArgs...)
	code = runWithConfig(allArgs, environ, &sb, &eb, runConfig{repoDir: repoDir})
	return sb.String(), eb.String(), code
}

// nsAgo returns a unix-nanosecond timestamp for "d ago".
func nsAgo(d time.Duration) int64 {
	return time.Now().Add(-d).UnixNano()
}

// --- consolidate() unit tests -----------------------------------------------

func TestConsolidate_AllUnreachable(t *testing.T) {
	results := []ServerResult{
		{ServerURL: "http://a", Reachable: false, Err: fmt.Errorf("dial error")},
		{ServerURL: "http://b", Reachable: false, Err: fmt.Errorf("dial error")},
	}
	con := consolidate(results, ModeQuorum, 15*time.Minute)
	if con.ExitCode != 2 {
		t.Fatalf("want exit 2, got %d", con.ExitCode)
	}
	if !strings.Contains(con.Reason, "unreachable") {
		t.Fatalf("expected 'unreachable' in reason, got: %q", con.Reason)
	}
}

func TestConsolidate_QuorumThreeOK(t *testing.T) {
	results := []ServerResult{
		{ServerURL: "http://a", Reachable: true, Status: "ok", Confidence: "authoritative", LastSyncedNS: nsAgo(5 * time.Minute)},
		{ServerURL: "http://b", Reachable: true, Status: "ok", Confidence: "authoritative", LastSyncedNS: nsAgo(5 * time.Minute)},
		{ServerURL: "http://c", Reachable: true, Status: "ok", Confidence: "authoritative", LastSyncedNS: nsAgo(5 * time.Minute)},
	}
	con := consolidate(results, ModeQuorum, 15*time.Minute)
	if con.FinalStatus != "ok" {
		t.Fatalf("want ok, got %q (reason: %s)", con.FinalStatus, con.Reason)
	}
	if con.ExitCode != 0 {
		t.Fatalf("want exit 0, got %d", con.ExitCode)
	}
}

// Quorum 2×ok + 1×tainted, all within freshness window → ok wins (majority),
// tainted appears in dissent.
func TestConsolidate_QuorumMajorityOKWithDissent(t *testing.T) {
	freshSyncNS := nsAgo(2 * time.Minute)
	results := []ServerResult{
		{ServerURL: "http://a", Reachable: true, Status: "ok", LastSyncedNS: freshSyncNS},
		{ServerURL: "http://b", Reachable: true, Status: "ok", LastSyncedNS: freshSyncNS},
		{ServerURL: "http://c", Reachable: true, Status: "tainted", LastSyncedNS: freshSyncNS},
	}
	// All synced at the same time → gap = 0, within 15m window.
	con := consolidate(results, ModeQuorum, 15*time.Minute)
	if con.FinalStatus != "ok" {
		t.Fatalf("want ok majority, got %q (reason: %s)", con.FinalStatus, con.Reason)
	}
	if con.ExitCode != 0 {
		t.Fatalf("want exit 0, got %d", con.ExitCode)
	}
	// Tainted server should appear in dissent.
	hasTaintedDissent := false
	for _, d := range con.Dissent {
		if d.Status == "tainted" {
			hasTaintedDissent = true
		}
	}
	if !hasTaintedDissent {
		t.Fatalf("expected tainted server in dissent, dissent=%v", con.Dissent)
	}
}

// KEY CASE: stale ok-majority + fresh tainted → tainted wins (freshness override).
func TestConsolidate_QuorumFreshnessOverrideTainted(t *testing.T) {
	window := 15 * time.Minute
	// Good servers last synced 3 hours ago (stale).
	goodSyncNS := nsAgo(3 * time.Hour)
	// Bad server synced 2 minutes ago (fresh, sees the tamper).
	badSyncNS := nsAgo(2 * time.Minute)
	// Gap = 3h - 2m = ~178m >> 15m window.

	results := []ServerResult{
		{ServerURL: "http://a", Reachable: true, Status: "ok", LastSyncedNS: goodSyncNS},
		{ServerURL: "http://b", Reachable: true, Status: "ok", LastSyncedNS: goodSyncNS},
		{ServerURL: "http://c", Reachable: true, Status: "tainted", LastSyncedNS: badSyncNS},
	}
	con := consolidate(results, ModeQuorum, window)
	if con.FinalStatus != "tainted" {
		t.Fatalf("want tainted (freshness override), got %q (reason: %s)", con.FinalStatus, con.Reason)
	}
	if con.ExitCode != 4 {
		t.Fatalf("want exit 4, got %d", con.ExitCode)
	}
	if !strings.Contains(con.Reason, "newer than freshest clean sync") {
		t.Fatalf("expected freshness reason, got: %q", con.Reason)
	}
	// Good servers that lost should be in dissent.
	if len(con.Dissent) == 0 {
		t.Fatal("expected good servers in dissent")
	}
}

// Freshness boundary: gap just UNDER the window → majority wins (ok).
func TestConsolidate_QuorumFreshnessBoundaryUnder(t *testing.T) {
	window := 15 * time.Minute
	// Good synced 16m ago, bad synced 2m ago → gap = 14m < 15m window.
	goodSyncNS := nsAgo(16 * time.Minute)
	badSyncNS := nsAgo(2 * time.Minute)

	results := []ServerResult{
		{ServerURL: "http://a", Reachable: true, Status: "ok", LastSyncedNS: goodSyncNS},
		{ServerURL: "http://b", Reachable: true, Status: "ok", LastSyncedNS: goodSyncNS},
		{ServerURL: "http://c", Reachable: true, Status: "tainted", LastSyncedNS: badSyncNS},
	}
	con := consolidate(results, ModeQuorum, window)
	// gap = badSyncNS - goodSyncNS = 14m < 15m window → no override → majority ok wins
	if con.FinalStatus != "ok" {
		t.Fatalf("want ok (gap under window), got %q (reason: %s)", con.FinalStatus, con.Reason)
	}
}

// Freshness boundary: gap just OVER the window → tainted override.
func TestConsolidate_QuorumFreshnessBoundaryOver(t *testing.T) {
	window := 15 * time.Minute
	// Good synced 17m ago, bad synced 1m ago → gap = 16m > 15m window.
	goodSyncNS := nsAgo(17 * time.Minute)
	badSyncNS := nsAgo(1 * time.Minute)

	results := []ServerResult{
		{ServerURL: "http://a", Reachable: true, Status: "ok", LastSyncedNS: goodSyncNS},
		{ServerURL: "http://b", Reachable: true, Status: "ok", LastSyncedNS: goodSyncNS},
		{ServerURL: "http://c", Reachable: true, Status: "tainted", LastSyncedNS: badSyncNS},
	}
	con := consolidate(results, ModeQuorum, window)
	if con.FinalStatus != "tainted" {
		t.Fatalf("want tainted (gap over window), got %q (reason: %s)", con.FinalStatus, con.Reason)
	}
	if con.ExitCode != 4 {
		t.Fatalf("want exit 4, got %d", con.ExitCode)
	}
}

func TestConsolidate_UnanimousDisagreement(t *testing.T) {
	results := []ServerResult{
		{ServerURL: "http://a", Reachable: true, Status: "ok"},
		{ServerURL: "http://b", Reachable: true, Status: "tainted"},
		{ServerURL: "http://c", Reachable: true, Status: "ok"},
	}
	con := consolidate(results, ModeUnanimous, 15*time.Minute)
	if con.FinalStatus != "no_consensus" {
		t.Fatalf("want no_consensus, got %q", con.FinalStatus)
	}
	if con.ExitCode != 7 {
		t.Fatalf("want exit 7, got %d", con.ExitCode)
	}
}

func TestConsolidate_UnanimousAgree(t *testing.T) {
	results := []ServerResult{
		{ServerURL: "http://a", Reachable: true, Status: "ok", Confidence: "authoritative"},
		{ServerURL: "http://b", Reachable: true, Status: "ok", Confidence: "authoritative"},
	}
	con := consolidate(results, ModeUnanimous, 15*time.Minute)
	if con.FinalStatus != "ok" {
		t.Fatalf("want ok, got %q (reason: %s)", con.FinalStatus, con.Reason)
	}
	if con.ExitCode != 0 {
		t.Fatalf("want exit 0, got %d", con.ExitCode)
	}
}

func TestConsolidate_AnyBadWithTainted(t *testing.T) {
	results := []ServerResult{
		{ServerURL: "http://a", Reachable: true, Status: "ok"},
		{ServerURL: "http://b", Reachable: true, Status: "tainted", LastSyncedNS: nsAgo(1 * time.Minute)},
	}
	con := consolidate(results, ModeAnyBad, 15*time.Minute)
	if con.FinalStatus != "tainted" {
		t.Fatalf("want tainted, got %q", con.FinalStatus)
	}
	if con.ExitCode != 4 {
		t.Fatalf("want exit 4, got %d", con.ExitCode)
	}
}

func TestConsolidate_AnyBadAllOK(t *testing.T) {
	results := []ServerResult{
		{ServerURL: "http://a", Reachable: true, Status: "ok"},
		{ServerURL: "http://b", Reachable: true, Status: "ok"},
	}
	con := consolidate(results, ModeAnyBad, 15*time.Minute)
	if con.FinalStatus != "ok" {
		t.Fatalf("want ok, got %q", con.FinalStatus)
	}
	if con.ExitCode != 0 {
		t.Fatalf("want exit 0, got %d", con.ExitCode)
	}
}

func TestConsolidate_FirstConclusiveWins(t *testing.T) {
	results := []ServerResult{
		{ServerURL: "http://a", Reachable: false, Err: fmt.Errorf("timeout")},
		{ServerURL: "http://b", Reachable: true, Status: "tainted"},
		{ServerURL: "http://c", Reachable: true, Status: "ok"},
	}
	// "first" in configured order: a=unreachable, b=tainted (conclusive) → tainted wins.
	con := consolidate(results, ModeFirst, 15*time.Minute)
	if con.FinalStatus != "tainted" {
		t.Fatalf("want tainted (first conclusive), got %q", con.FinalStatus)
	}
	if con.ExitCode != 4 {
		t.Fatalf("want exit 4, got %d", con.ExitCode)
	}
}

func TestConsolidate_FirstInconclusiveFallback(t *testing.T) {
	results := []ServerResult{
		{ServerURL: "http://a", Reachable: false, Err: fmt.Errorf("timeout")},
		{ServerURL: "http://b", Reachable: true, Status: "not_tracked"},
	}
	con := consolidate(results, ModeFirst, 15*time.Minute)
	if con.FinalStatus != "not_tracked" {
		t.Fatalf("want not_tracked (first inconclusive), got %q", con.FinalStatus)
	}
	if con.ExitCode != 6 {
		t.Fatalf("want exit 6, got %d", con.ExitCode)
	}
}

// --- Integration tests against httptest servers ----------------------------

// TestMulti_SingleServerBackcompat verifies the single-server path still
// produces the same exit codes and output as before.
func TestMulti_SingleServerBackcompat(t *testing.T) {
	repoDir, _, _ := setupFixtureRepo(t)

	for _, tc := range []struct {
		name     string
		resp     verifyResponse
		wantCode int
		wantOut  string
	}{
		{"ok", verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0"}, 0, "ok:"},
		{"mismatch", verifyResponse{Status: "mismatch", Confidence: "authoritative", Tag: "v1.0.0"}, 3, "MISMATCH"},
		{"tainted", verifyResponse{Status: "tainted", Confidence: "authoritative", Tag: "v1.0.0"}, 4, "TAINTED"},
		{"doesnt_exist", verifyResponse{Status: "doesnt_exist", Confidence: "authoritative", Tag: "v1.0.0"}, 5, "not found"},
		{"not_tracked", verifyResponse{Status: "not_tracked", Confidence: "authoritative", Tag: "v1.0.0"}, 6, "not tracked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := cannedServer(t, tc.resp)
			var stdout, stderr strings.Builder
			code := runWithConfig(
				[]string{"--server", srv.URL, "--url", "https://github.com/example/repo.git", "--tag", "v1.0.0"},
				nil, &stdout, &stderr,
				runConfig{repoDir: repoDir},
			)
			if code != tc.wantCode {
				t.Fatalf("want exit %d, got %d; stdout=%q stderr=%q", tc.wantCode, code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.wantOut) {
				t.Fatalf("want %q in output, got: %q", tc.wantOut, stdout.String())
			}
		})
	}
}

// TestMulti_ThreeOKQuorum verifies 3×ok → exit 0.
func TestMulti_ThreeOKQuorum(t *testing.T) {
	srv1 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: ptrTo(nsAgo(2 * time.Minute))})
	srv2 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: ptrTo(nsAgo(2 * time.Minute))})
	srv3 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: ptrTo(nsAgo(2 * time.Minute))})

	stdout, stderr, code := runMulti(t,
		[]string{"--server", srv1.URL, "--server", srv2.URL, "--server", srv3.URL, "--mode", "quorum"},
		nil,
	)
	if code != 0 {
		t.Fatalf("want exit 0, got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "quorum: OK") {
		t.Fatalf("expected 'quorum: OK' in output, got: %q", stdout)
	}
}

// TestMulti_QuorumMajorityOKDissentShown verifies 2×ok + 1×tainted (all fresh,
// within window) → exit 0 + dissent line shown.
func TestMulti_QuorumMajorityOKDissentShown(t *testing.T) {
	freshNS := nsAgo(2 * time.Minute)
	srvOK1 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: &freshNS})
	srvOK2 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: &freshNS})
	srvTaint := cannedServerWithSync(t, verifyResponse{Status: "tainted", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: &freshNS})

	stdout, stderr, code := runMulti(t,
		[]string{
			"--server", srvOK1.URL,
			"--server", srvOK2.URL,
			"--server", srvTaint.URL,
			"--mode", "quorum",
			"--freshness-window", "15m",
		},
		nil,
	)
	if code != 0 {
		t.Fatalf("want exit 0 (majority ok), got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "dissent") {
		t.Fatalf("expected dissent line in output, got: %q", stdout)
	}
}

// TestMulti_QuorumFreshnessOverride is the KEY case:
// stale 2×ok + fresh 1×tainted → tainted wins (exit 4).
func TestMulti_QuorumFreshnessOverride(t *testing.T) {
	staleNS := nsAgo(3 * time.Hour)
	freshNS := nsAgo(2 * time.Minute)

	srvOK1 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "stale", Tag: "v1.0.0", LastSyncedNS: &staleNS})
	srvOK2 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "stale", Tag: "v1.0.0", LastSyncedNS: &staleNS})
	srvTaint := cannedServerWithSync(t, verifyResponse{Status: "tainted", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: &freshNS})

	stdout, stderr, code := runMulti(t,
		[]string{
			"--server", srvOK1.URL,
			"--server", srvOK2.URL,
			"--server", srvTaint.URL,
			"--mode", "quorum",
			"--freshness-window", "15m",
		},
		nil,
	)
	if code != 4 {
		t.Fatalf("KEY CASE: want exit 4 (fresh tainted overrides stale majority), got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "quorum: TAINTED") {
		t.Fatalf("want 'quorum: TAINTED' in output, got: %q", stdout)
	}
	if !strings.Contains(stdout, "newer than freshest clean sync") {
		t.Fatalf("want freshness reason in output, got: %q", stdout)
	}
}

// TestMulti_UnanimousDisagreement verifies unanimous mode → exit 7.
func TestMulti_UnanimousDisagreement(t *testing.T) {
	srvOK := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0"})
	srvTaint := cannedServerWithSync(t, verifyResponse{Status: "tainted", Confidence: "authoritative", Tag: "v1.0.0"})

	stdout, stderr, code := runMulti(t,
		[]string{"--server", srvOK.URL, "--server", srvTaint.URL, "--mode", "unanimous"},
		nil,
	)
	if code != 7 {
		t.Fatalf("want exit 7 (no_consensus), got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "NO_CONSENSUS") {
		t.Fatalf("want 'NO_CONSENSUS' in output, got: %q", stdout)
	}
}

// TestMulti_AnyBadOneTainted verifies any-bad → exit 4 if any server says tainted.
func TestMulti_AnyBadOneTainted(t *testing.T) {
	srvOK := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0"})
	srvTaint := cannedServerWithSync(t, verifyResponse{Status: "tainted", Confidence: "authoritative", Tag: "v1.0.0"})

	stdout, stderr, code := runMulti(t,
		[]string{"--server", srvOK.URL, "--server", srvTaint.URL, "--mode", "any-bad"},
		nil,
	)
	if code != 4 {
		t.Fatalf("want exit 4 (any-bad tainted), got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
	_ = stdout
	_ = stderr
}

// TestMulti_FirstMode verifies first mode picks the first conclusive server in order.
func TestMulti_FirstMode(t *testing.T) {
	// Server 1 returns tainted; server 2 returns ok.
	srvTaint := cannedServerWithSync(t, verifyResponse{Status: "tainted", Confidence: "authoritative", Tag: "v1.0.0"})
	srvOK := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0"})

	stdout, stderr, code := runMulti(t,
		[]string{"--server", srvTaint.URL, "--server", srvOK.URL, "--mode", "first"},
		nil,
	)
	// first conclusive = srvTaint (exit 4)
	if code != 4 {
		t.Fatalf("want exit 4 (first=tainted), got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// TestMulti_AllUnreachable verifies exit 2 when no server responds.
func TestMulti_AllUnreachable(t *testing.T) {
	// Both servers return 503 (unreachable).
	bad1 := unavailableServer(t)
	bad2 := unavailableServer(t)

	stdout, stderr, code := runMulti(t,
		[]string{"--server", bad1.URL, "--server", bad2.URL},
		nil,
	)
	if code != 2 {
		t.Fatalf("want exit 2 (all unreachable), got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
	_ = stdout
}

// TestMulti_JSONShape verifies --json emits the multi-server JSON object with expected fields.
func TestMulti_JSONShape(t *testing.T) {
	staleNS := nsAgo(3 * time.Hour)
	freshNS := nsAgo(2 * time.Minute)

	srvOK1 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "stale", Tag: "v1.0.0", LastSyncedNS: &staleNS})
	srvOK2 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "stale", Tag: "v1.0.0", LastSyncedNS: &staleNS})
	srvTaint := cannedServerWithSync(t, verifyResponse{Status: "tainted", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: &freshNS})

	stdout, stderr, code := runMulti(t,
		[]string{
			"--server", srvOK1.URL,
			"--server", srvOK2.URL,
			"--server", srvTaint.URL,
			"--mode", "quorum",
			"--freshness-window", "15m",
			"--json",
		},
		nil,
	)
	if code != 4 {
		t.Fatalf("KEY CASE (json): want exit 4, got %d; stderr=%q", code, stderr)
	}

	var out multiJSONOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("JSON parse error: %v\noutput: %q", err, stdout)
	}
	if out.Mode != ModeQuorum {
		t.Fatalf("JSON mode: want %q, got %q", ModeQuorum, out.Mode)
	}
	if out.FinalStatus != "tainted" {
		t.Fatalf("JSON final_status: want %q, got %q", "tainted", out.FinalStatus)
	}
	if out.ExitCode != 4 {
		t.Fatalf("JSON exit_code: want 4, got %d", out.ExitCode)
	}
	if len(out.Servers) != 3 {
		t.Fatalf("JSON servers: want 3, got %d", len(out.Servers))
	}
	if out.FreshnessWindowNS == 0 {
		t.Fatal("JSON freshness_window_ns: want non-zero")
	}
	// Dissent should contain the 2 ok servers.
	if len(out.Dissent) != 2 {
		t.Fatalf("JSON dissent: want 2 (the stale-ok servers), got %d", len(out.Dissent))
	}
	for _, d := range out.Dissent {
		if d.Status != "ok" {
			t.Fatalf("JSON dissent entry: want ok, got %q", d.Status)
		}
	}
}

// TestMulti_GTServersEnvVar verifies GT_SERVERS (comma-separated) is respected.
func TestMulti_GTServersEnvVar(t *testing.T) {
	srv1 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0"})
	srv2 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0"})

	stdout, stderr, code := runMulti(t,
		[]string{"--mode", "unanimous"},
		[]string{"GT_SERVERS=" + srv1.URL + "," + srv2.URL},
	)
	if code != 0 {
		t.Fatalf("want exit 0, got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// TestMulti_GTModeEnvVar verifies GT_MODE env var is respected.
func TestMulti_GTModeEnvVar(t *testing.T) {
	srvOK := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0"})
	srvTaint := cannedServerWithSync(t, verifyResponse{Status: "tainted", Confidence: "authoritative", Tag: "v1.0.0"})

	stdout, stderr, code := runMulti(t,
		[]string{"--server", srvOK.URL, "--server", srvTaint.URL},
		[]string{"GT_MODE=any-bad"},
	)
	// any-bad: tainted present → exit 4
	if code != 4 {
		t.Fatalf("want exit 4 (GT_MODE=any-bad), got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// TestMulti_FlagOverridesEnvMode verifies --mode flag beats GT_MODE env.
func TestMulti_FlagOverridesEnvMode(t *testing.T) {
	freshNS := nsAgo(2 * time.Minute)
	srvOK1 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: &freshNS})
	srvOK2 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: &freshNS})
	srvTaint := cannedServerWithSync(t, verifyResponse{Status: "tainted", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: &freshNS})

	// GT_MODE=any-bad would give exit 4, but --mode quorum with 2/3 majority → exit 0.
	stdout, stderr, code := runMulti(t,
		[]string{
			"--server", srvOK1.URL,
			"--server", srvOK2.URL,
			"--server", srvTaint.URL,
			"--mode", "quorum",
			"--freshness-window", "15m",
		},
		[]string{"GT_MODE=any-bad"},
	)
	if code != 0 {
		t.Fatalf("want exit 0 (--mode quorum beats GT_MODE=any-bad), got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// TestMulti_DeduplicateServers verifies that duplicate server URLs are deduplicated.
func TestMulti_DeduplicateServers(t *testing.T) {
	// Use a counter to verify the server is only called once per URL.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/verify" {
			callCount++
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0"})
	}))
	t.Cleanup(srv.Close)

	stdout, stderr, code := runMulti(t,
		// Same URL twice → should be deduplicated to one server → single-server path.
		[]string{"--server", srv.URL, "--server", srv.URL},
		nil,
	)
	if code != 0 {
		t.Fatalf("want exit 0, got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if callCount != 1 {
		t.Fatalf("server called %d times after dedup (want 1)", callCount)
	}
}

// TestMulti_FreshnessWindowEnvVar verifies GT_FRESHNESS_WINDOW_NS is respected.
func TestMulti_FreshnessWindowEnvVar(t *testing.T) {
	// Good synced 20m ago, bad synced 5m ago → gap = 15m.
	// Default window 15m: gap == window (not >) → majority ok wins.
	// Custom window 10m:  gap > window → tainted wins.
	goodSyncNS := nsAgo(20 * time.Minute)
	badSyncNS := nsAgo(5 * time.Minute)

	srvOK1 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: &goodSyncNS})
	srvOK2 := cannedServerWithSync(t, verifyResponse{Status: "ok", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: &goodSyncNS})
	srvTaint := cannedServerWithSync(t, verifyResponse{Status: "tainted", Confidence: "authoritative", Tag: "v1.0.0", LastSyncedNS: &badSyncNS})

	// Narrow window (10m in ns): gap 15m > 10m → tainted override.
	tenMinNS := fmt.Sprintf("%d", int64(10*time.Minute))
	stdout, stderr, code := runMulti(t,
		[]string{
			"--server", srvOK1.URL,
			"--server", srvOK2.URL,
			"--server", srvTaint.URL,
			"--mode", "quorum",
		},
		[]string{"GT_FRESHNESS_WINDOW_NS=" + tenMinNS},
	)
	if code != 4 {
		t.Fatalf("want exit 4 (10m window, 15m gap), got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
	_ = stdout
}
