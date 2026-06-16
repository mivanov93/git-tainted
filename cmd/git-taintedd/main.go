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

Key environment variables (see .env.example for the full list):
  GT_DB_DRIVER     sqlite (default) | mysql
  GT_SQLITE_PATH   SQLite DB path (driver=sqlite)
  GT_MYSQL_DSN     MySQL DSN (driver=mysql; needs multiStatements=true&clientFoundRows=true)
  GT_LISTEN_ADDR   HTTP listen address (default 127.0.0.1:8080; serves HTTP/1.1 + h2c)
  GT_METRICS_ADDR  Prometheus metrics address
  GT_SYNC_DEFAULT_INTERVAL_NS  GT_SCHEDULER_TICK_NS  GT_STALENESS_BUDGET_NS
  GT_GIT_BIN  GT_GIT_TIMEOUT_NS  GT_PROTOCOL_ALLOWLIST  GT_LOG_LEVEL
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

	// ---- HTTP handler ---------------------------------------------------------
	metrics := api.NewMetrics()
	apiHandler := api.NewServer(st, clk, syncer)
	opsHandler := api.OpsHandlerFull(st, metrics)

	// Mount ops routes alongside the API routes. API routes are all under /v1/
	// and /healthz; ops adds /readyz, /metrics, /debug/pprof.
	mux := http.NewServeMux()
	mux.Handle("/", apiHandler)
	mux.Handle("/readyz", opsHandler)
	mux.Handle("/metrics", opsHandler)
	mux.Handle("/debug/pprof/", opsHandler)
	mux.Handle("/debug/pprof/cmdline", opsHandler)
	mux.Handle("/debug/pprof/profile", opsHandler)
	mux.Handle("/debug/pprof/symbol", opsHandler)
	mux.Handle("/debug/pprof/trace", opsHandler)

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

	log.Info("server ready", "listen_addr", cfg.ListenAddr, "metrics_addr", cfg.MetricsAddr)

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
		return nil

	case err := <-errCh:
		schedCancel()
		<-schedDone
		if err != nil {
			log.Error("http server failed", "err", err)
		}
		return err
	}
}

// Ensure model.Clock is satisfied by wallClock at compile time.
var _ model.Clock = wallClock{}
