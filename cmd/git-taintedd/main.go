// Command git-taintedd is the git-tainted server. It wires config, logging,
// the SQLite Store, seams (Clock/Lock/GitRunner/RemoteSyncer), the HTTP API
// handler, the Scheduler goroutine, and graceful shutdown (§6, §11, §12).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mivanov93/git-tainted/db"
	"github.com/mivanov93/git-tainted/internal/api"
	"github.com/mivanov93/git-tainted/internal/auth"
	"github.com/mivanov93/git-tainted/internal/buildinfo"
	"github.com/mivanov93/git-tainted/internal/config"
	"github.com/mivanov93/git-tainted/internal/git"
	"github.com/mivanov93/git-tainted/internal/lock"
	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/store/mysql"
	"github.com/mivanov93/git-tainted/internal/store/sqlite"
	tlsync "github.com/mivanov93/git-tainted/internal/sync"
)

func main() {
	if code, handled := handleFlags(os.Args[1:], os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}
	if err := run(); err != nil {
		// run already logged the cause; exit non-zero for the supervisor.
		os.Exit(1)
	}
}

// handleFlags processes --version/-v and --help/-h before the env-driven server
// starts. It returns (exitCode, handled): handled==true means the caller should
// exit with exitCode without running the server. Normal startup passes no flags,
// so it returns (0, false) and run() proceeds.
func handleFlags(args []string, stdout, stderr io.Writer) (int, bool) {
	fs := flag.NewFlagSet("git-taintedd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { _, _ = fmt.Fprint(stdout, serverUsage) }
	var versionFlag bool
	fs.BoolVar(&versionFlag, "version", false, "Print version and exit")
	fs.BoolVar(&versionFlag, "v", false, "Print version and exit (shorthand)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true // -h/--help: usage already printed to stdout
		}
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 2, true
	}
	if versionFlag {
		_, _ = fmt.Fprintf(stdout, "git-taintedd %s\n", buildinfo.String())
		return 0, true
	}
	return 0, false
}

const serverUsage = `git-taintedd — the git-tainted server.

Polls registered git remotes (via ` + "`git ls-remote --tags`" + `), records each
tag's oid in an append-only, per-remote, SHA-256 hash-chained ledger, and serves
the verify/admin API. Configured entirely via GT_* environment variables;
migrations are embedded in the binary (no db/ folder needed at runtime).

Usage:
  git-taintedd [--version|-v] [--help|-h]

Environment variables (all GT_*):

  Database
  --------
  GT_DB_DRIVER                 Storage backend: sqlite (default) or mysql
  GT_SQLITE_PATH               Path to the SQLite DB file (required if driver=sqlite)
  GT_MYSQL_DSN                 MySQL DSN (required if driver=mysql);
                               needs multiStatements=true&parseTime=false&clientFoundRows=true

  HTTP server
  -----------
  GT_LISTEN_ADDR               API listen address          (default: 127.0.0.1:8080)
                               Serves HTTP/1.1 + h2c on a single cleartext listener.

  Scheduler / sync
  ----------------
  GT_SYNC_CONCURRENCY          Max concurrent in-flight syncs        (default: 4)
  GT_SYNC_DEFAULT_INTERVAL_NS  Default sync interval in unix-ns       (default: 300000000000  = 5 min)
  GT_SCHEDULER_TICK_NS         Scheduler wake-up tick interval in ns  (default: 5000000000   = 5 s)
  GT_STALENESS_BUDGET_NS       How far past due a sync may be before
                               it is considered stale, in ns           (default: 3600000000000 = 1 h)

  Git runner
  ----------
  GT_GIT_BIN                   Path or name of the git binary         (default: git)
  GT_GIT_TIMEOUT_NS            Per-ls-remote deadline in ns           (default: 60000000000 = 60 s)
  GT_PROTOCOL_ALLOWLIST        Colon-separated git transport schemes
                               the syncer will accept                  (default: https:ssh)
  GT_HOST_ALLOWLIST            Colon-separated allowed host patterns;
                               empty = allow all                       (default: "")

  Observability
  -------------
  GT_LOG_LEVEL                 Structured log level: debug|info|warn|error (default: info)
  GT_METRICS_ADDR              Dedicated Prometheus listener address.
                               Empty (default) = metrics DISABLED — no /metrics endpoint,
                               no collection. Set to e.g. 127.0.0.1:9090 to enable.
  GT_PPROF_ENABLED             Expose /debug/pprof/* on the API listener (default: false).
                               Set to true only in controlled environments.

  Auth (control endpoints only)
  -----------------------------
  Gates ONLY the five mutating control operations (create/update/delete remote,
  trigger sync, ack taint event). Reads (verify, all GETs) and health probes are
  never gated. Default mode "none" reproduces the loopback/edge-proxy posture.

  GT_AUTH_MODE                 none (default) | apikey | basic | jwks.
                               Unknown value is a fatal startup error.
  GT_API_KEYS                  apikey mode: comma-separated raw keys. Each is
                               SHA-256-hashed at load and the cleartext dropped.
  GT_API_KEYS_SHA256           apikey mode: comma-separated lowercase-hex SHA-256
                               key digests (raw key never enters the env).
                               apikey mode needs at least one key via either var.
                               Client sends Authorization: Bearer <key> or X-API-Key.
  GT_BASIC_AUTH                basic mode: comma-separated user:bcrypt-hash entries
                               (htpasswd-style; raw passwords never in the env).
                               Client sends HTTP Basic. At least one entry required.
  GT_JWKS_URL                  jwks mode: JWKS endpoint URL (required).
  GT_JWT_ISSUER                jwks mode: expected iss claim (required).
  GT_JWT_AUDIENCE              jwks mode: expected aud claim (required).
  GT_JWT_ALGS                  jwks mode: comma-separated signature-algorithm
                               allowlist (default: RS256,ES256). "none" and all
                               HS* algorithms are always rejected.
`

// wallClock is the real time implementation of model.Clock.
type wallClock struct{}

func (wallClock) NowNS() int64 { return time.Now().UnixNano() }

func run() error {
	cfg, err := config.LoadEnv()
	if err != nil {
		// No logger yet; emit the config failure to stderr via a bootstrap logger.
		config.NewLogger(os.Stderr, "error").Error("config load failed", "err", err)
		return err
	}
	log := config.NewLogger(os.Stdout, cfg.LogLevel)

	// ---- Store ----------------------------------------------------------------
	// Two model.Store implementations behind one seam (owner's two-impls pattern):
	// sqlite (default) and mysql, each in its own subpackage. Migrations are
	// embedded in the binary (the db package) and applied by Open — the server
	// runs with no db/ folder on disk.
	var st model.Store
	switch cfg.DBDriver {
	case "mysql":
		// mysql.Open pings, runs the embedded MySQL migrations, returns a ready store.
		st, err = mysql.Open(cfg.MySQLDSN, db.MySQLMigrations)
		if err != nil {
			log.Error("mysql.Open failed", "err", err)
			return err
		}
		defer func() { _ = st.Close() }()
		log.Info("store ready", "driver", "mysql")
	default: // "sqlite" (validated in config)
		// sqlite.Open pings, applies the embedded SQLite migrations, returns a ready store.
		st, err = sqlite.Open(cfg.SQLitePath, db.SQLiteMigrations)
		if err != nil {
			log.Error("sqlite.Open failed", "path", cfg.SQLitePath, "err", err)
			return err
		}
		defer func() { _ = st.Close() }()
		log.Info("store ready", "driver", "sqlite", "path", cfg.SQLitePath)
	}

	// ---- Seams ----------------------------------------------------------------
	clk := wallClock{}
	lk := lock.NewDBLease(st, clk)
	gitRunner := git.NewExecGitRunner(git.Config{
		GitBin:        cfg.GitBin,
		TimeoutNS:     cfg.GitTimeoutNS,
		ProtocolAllow: cfg.ProtocolAllowlist,
	})
	// holder identifies this process in the lease table.
	holder := fmt.Sprintf("git-taintedd-%d", os.Getpid())
	syncer := tlsync.NewRemoteSyncer(st, gitRunner, lk, clk, holder)

	// ---- Auth -----------------------------------------------------------------
	// Build the control-plane authenticator from config (default mode=none =
	// today's loopback/edge-proxy posture). Misconfiguration (apikey with no keys,
	// jwks without url/issuer/audience, basic with no users / bad hash) is fatal
	// here at startup — never a per-request failure. authCtx bounds the jwks
	// background-refresh goroutine to the process lifetime.
	authCtx, authCancel := context.WithCancel(context.Background())
	defer authCancel()
	authn, err := auth.FromConfig(authCtx, cfg)
	if err != nil {
		log.Error("auth init failed", "mode", cfg.AuthMode, "err", err)
		return err
	}
	log.Info("auth ready", "mode", cfg.AuthMode)

	// ---- HTTP handler ---------------------------------------------------------
	apiHandler := api.NewServer(st, clk, syncer, authn, log)
	// OpsHandler mounts /healthz, /readyz, and conditionally /debug/pprof/*.
	opsHandler := api.OpsHandler(st, cfg.PprofEnabled)

	// Mount ops routes alongside the API routes. API routes are all under /v1/.
	// /metrics is served on the dedicated metrics listener only (when configured).
	mux := http.NewServeMux()
	mux.Handle("/", apiHandler)
	mux.Handle("/healthz", opsHandler)
	mux.Handle("/readyz", opsHandler)
	if cfg.PprofEnabled {
		mux.Handle("/debug/pprof/", opsHandler)
		mux.Handle("/debug/pprof/cmdline", opsHandler)
		mux.Handle("/debug/pprof/profile", opsHandler)
		mux.Handle("/debug/pprof/symbol", opsHandler)
		mux.Handle("/debug/pprof/trace", opsHandler)
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	// Serve both HTTP/1.1 and unencrypted HTTP/2 (h2c) on the cleartext listener.
	// Go 1.24+ native support — no golang.org/x/net/http2/h2c wrapper.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv.Protocols = protocols

	// ---- Metrics server (optional) -------------------------------------------
	// When GT_METRICS_ADDR is non-empty, start a dedicated listener that exposes
	// only GET /metrics. When empty (default), no metrics are collected or served.
	var metricsSrv *http.Server
	if cfg.MetricsAddr != "" {
		m := api.NewMetrics()
		metricsSrv = &http.Server{
			Addr:              cfg.MetricsAddr,
			Handler:           api.MetricsHandler(m),
			ReadHeaderTimeout: 10 * time.Second,
		}
		metricsErrCh := make(chan error, 1)
		go func() {
			log.Info("metrics server starting", "addr", cfg.MetricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				metricsErrCh <- err
				return
			}
			metricsErrCh <- nil
		}()
		// Capture the channel so shutdown can drain it later.
		_ = metricsErrCh
	}

	// ---- Signal context -------------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ---- Scheduler ------------------------------------------------------------
	sched := tlsync.NewScheduler(st, syncer, clk, log, cfg.SchedulerTickNS, cfg.SyncConcurrency)

	schedCtx, schedCancel := context.WithCancel(context.Background())
	schedDone := make(chan struct{})
	go func() {
		defer close(schedDone)
		sched.Start(schedCtx)
	}()

	// ---- HTTP server ----------------------------------------------------------
	errCh := make(chan error, 1)
	go func() {
		log.Info("http server starting", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	if cfg.MetricsAddr != "" {
		log.Info("server ready", "listen_addr", cfg.ListenAddr, "metrics_addr", cfg.MetricsAddr, "pprof", cfg.PprofEnabled)
	} else {
		log.Info("server ready", "listen_addr", cfg.ListenAddr, "metrics", "disabled", "pprof", cfg.PprofEnabled)
	}

	// ---- Graceful shutdown ----------------------------------------------------
	select {
	case <-ctx.Done():
		log.Info("shutdown signal received, draining")

		// 1. Stop scheduler (drain in-flight syncs).
		schedCancel()
		<-schedDone
		log.Info("scheduler drained")

		// 2. Shutdown HTTP server.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("graceful shutdown failed", "err", err)
			return err
		}
		log.Info("http server drained cleanly")

		// 3. Shutdown metrics server (if running).
		if metricsSrv != nil {
			mShutCtx, mCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer mCancel()
			if err := metricsSrv.Shutdown(mShutCtx); err != nil {
				log.Error("metrics server shutdown failed", "err", err)
			} else {
				log.Info("metrics server drained cleanly")
			}
		}
		return nil

	case err := <-errCh:
		schedCancel()
		<-schedDone
		if metricsSrv != nil {
			mShutCtx, mCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer mCancel()
			_ = metricsSrv.Shutdown(mShutCtx)
		}
		if err != nil {
			log.Error("http server failed", "err", err)
		}
		return err
	}
}

// Ensure model.Clock is satisfied by wallClock at compile time.
var _ model.Clock = wallClock{}
