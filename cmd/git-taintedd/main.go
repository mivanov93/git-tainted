// Command git-taintedd is the git-tainted server. It wires config, logging,
// the SQLite Store, seams (Clock/Lock/GitRunner/RemoteSyncer), the HTTP API
// handler, the Scheduler goroutine, and graceful shutdown (§6, §11, §12).
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mivanov93/git-tainted/db"
	"github.com/mivanov93/git-tainted/internal/api"
	"github.com/mivanov93/git-tainted/internal/config"
	"github.com/mivanov93/git-tainted/internal/git"
	"github.com/mivanov93/git-tainted/internal/lock"
	"github.com/mivanov93/git-tainted/internal/model"
	"github.com/mivanov93/git-tainted/internal/store/mysql"
	"github.com/mivanov93/git-tainted/internal/store/sqlite"
	tlsync "github.com/mivanov93/git-tainted/internal/sync"
)

func main() {
	if err := run(); err != nil {
		// run already logged the cause; exit non-zero for the supervisor.
		os.Exit(1)
	}
}

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
