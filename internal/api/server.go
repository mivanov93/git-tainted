// Package api wires the HTTP server: ops probes, and the OpenAPI-generated
// StrictServerInterface backed by model.Store + model.Clock.
package api

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mivanov93/git-tainted/internal/api/oapi"
	"github.com/mivanov93/git-tainted/internal/auth"
	"github.com/mivanov93/git-tainted/internal/model"
	tlsync "github.com/mivanov93/git-tainted/internal/sync"
)

// StrictServerImpl implements oapi.StrictServerInterface and is the single
// handler struct for all API operations. It holds the Store (persistence seam),
// Clock (time seam), and RemoteSyncer (sync seam) so all handlers are pure
// functions of the request. log is used only for audit lines on mutating
// operations; it is never nil (NewServer substitutes a discard logger).
type StrictServerImpl struct {
	store  model.Store
	clock  model.Clock
	syncer *tlsync.RemoteSyncer // may be nil (ops-only mode / tests that don't need sync)
	log    *slog.Logger
}

// discardLogger is a no-op logger used when a caller passes nil.
var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// NewServer builds the routed http.Handler for the git-tainted API.
// The /healthz route is handled by the generated oapi router; OpsHandler
// endpoints (readyz, etc.) are layered above if needed by the caller.
// syncer may be nil; TriggerSync will return 202 without starting a sync.
//
// authn gates the five mutating control operations (create/update/delete remote,
// trigger sync, ack taint event). Pass auth.None() to disable gating (the default
// posture). The enforcement middleware wraps the generated router so it runs
// before any handler or Store call; reads and health probes are never gated.
//
// log receives audit lines for each mutating operation (with the authenticated
// principal); pass nil to discard them.
func NewServer(s model.Store, c model.Clock, syncer *tlsync.RemoteSyncer, authn auth.Authenticator, log *slog.Logger) http.Handler {
	if log == nil {
		log = discardLogger
	}
	impl := &StrictServerImpl{store: s, clock: c, syncer: syncer, log: log}
	si := oapi.NewStrictHandlerWithOptions(impl, nil, oapi.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: requestErrorHandler,
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		},
	})
	return limitBody(auth.Middleware(authn)(oapi.Handler(si)))
}

// maxRequestBodyBytes caps request bodies. The control-plane payloads (create /
// update remote, ack taint) are a few hundred bytes, so 1 MiB is generous. The
// cap defends against memory exhaustion: without it the generated JSON decoder
// buffers the entire body before validation, so a large body can OOM the process.
const maxRequestBodyBytes = 1 << 20 // 1 MiB

// limitBody wraps each request body in http.MaxBytesReader so an oversized payload
// is cut off at the cap — the decoder then fails fast with *http.MaxBytesError
// instead of the whole body being read into memory.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// requestErrorHandler maps request decode/binding errors to status codes: an
// oversized body (from limitBody's MaxBytesReader) becomes 413 Request Entity Too
// Large; every other decode error keeps the generated default of 400.
func requestErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	// MaxBytesReader overflow → 413. Under GOEXPERIMENT=jsonv2 the jsontext decoder
	// wraps the *http.MaxBytesError without an Unwrap chain, so errors.As can miss
	// it; fall back to its stable stdlib message ("http: request body too large").
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) || strings.Contains(err.Error(), "request body too large") {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}
