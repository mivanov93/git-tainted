// Package api wires the HTTP server: ops probes, and the OpenAPI-generated
// StrictServerInterface backed by model.Store + model.Clock.
package api

import (
	"net/http"

	"github.com/mivanov93/git-tainted/internal/api/oapi"
	"github.com/mivanov93/git-tainted/internal/model"
	tlsync "github.com/mivanov93/git-tainted/internal/sync"
)

// StrictServerImpl implements oapi.StrictServerInterface and is the single
// handler struct for all API operations. It holds the Store (persistence seam),
// Clock (time seam), and RemoteSyncer (sync seam) so all handlers are pure
// functions of the request.
type StrictServerImpl struct {
	store  model.Store
	clock  model.Clock
	syncer *tlsync.RemoteSyncer // may be nil (ops-only mode / tests that don't need sync)
}

// NewServer builds the routed http.Handler for the git-tainted API.
// The /healthz route is handled by the generated oapi router; OpsHandler
// endpoints (readyz, etc.) are layered above if needed by the caller.
// syncer may be nil; TriggerSync will return 202 without starting a sync.
func NewServer(s model.Store, c model.Clock, syncer *tlsync.RemoteSyncer) http.Handler {
	impl := &StrictServerImpl{store: s, clock: c, syncer: syncer}
	si := oapi.NewStrictHandler(impl, nil)
	return oapi.Handler(si)
}
