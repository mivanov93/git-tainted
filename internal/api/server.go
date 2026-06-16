// Package api wires the HTTP server: ops probes, and the OpenAPI-generated
// StrictServerInterface backed by model.Store + model.Clock.
package api

import (
	"io"
	"log/slog"
	"net/http"

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
	si := oapi.NewStrictHandler(impl, nil)
	return auth.Middleware(authn)(oapi.Handler(si))
}
