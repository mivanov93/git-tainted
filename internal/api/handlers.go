package api

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/mivanov93/git-tainted/internal/api/oapi"
	"github.com/mivanov93/git-tainted/internal/auth"
	"github.com/mivanov93/git-tainted/internal/git"
	"github.com/mivanov93/git-tainted/internal/model"
)

// principalOf returns the authenticated principal for an audit line. Under
// auth=none (or any open path) the middleware injects "anonymous"; if no
// principal is present at all it falls back to "anonymous" so audit lines always
// carry a value.
func principalOf(ctx context.Context) string {
	if p, ok := auth.PrincipalFromContext(ctx); ok && p != "" {
		return p
	}
	return auth.AnonymousPrincipal
}

// GetHealthz implements GET /healthz.
func (s *StrictServerImpl) GetHealthz(_ context.Context, _ oapi.GetHealthzRequestObject) (oapi.GetHealthzResponseObject, error) {
	return oapi.GetHealthz200TextResponse("ok"), nil
}

// ---- Remotes ---------------------------------------------------------------

// ListRemotes implements GET /v1/remotes.
func (s *StrictServerImpl) ListRemotes(ctx context.Context, req oapi.ListRemotesRequestObject) (oapi.ListRemotesResponseObject, error) {
	// If ?url= provided, resolve a single remote by normalized URL.
	if req.Params.Url != nil && *req.Params.Url != "" {
		normURL, err := git.NormalizeURL(*req.Params.Url)
		if err != nil {
			normURL = *req.Params.Url // fallback: try the raw value
		}
		r, err := s.store.GetRemoteByURL(ctx, normURL)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				return oapi.ListRemotes200JSONResponse(oapi.RemoteList{Items: []oapi.Remote{}}), nil
			}
			return nil, err
		}
		return oapi.ListRemotes200JSONResponse(oapi.RemoteList{Items: []oapi.Remote{remoteToOAPI(*r)}}), nil
	}

	limit := 100
	if req.Params.Limit != nil && *req.Params.Limit > 0 {
		limit = *req.Params.Limit
	}
	if limit > 1000 {
		limit = 1000
	}
	cursor := int64(0)
	if req.Params.Cursor != nil {
		cursor = *req.Params.Cursor
	}

	remotes, nextCursor, err := s.store.ListRemotes(ctx, limit, cursor)
	if err != nil {
		return nil, err
	}
	items := make([]oapi.Remote, 0, len(remotes))
	for _, r := range remotes {
		items = append(items, remoteToOAPI(r))
	}
	return oapi.ListRemotes200JSONResponse(oapi.RemoteList{
		Items:      items,
		NextCursor: &nextCursor,
	}), nil
}

// CreateRemote implements POST /v1/remotes.
func (s *StrictServerImpl) CreateRemote(ctx context.Context, req oapi.CreateRemoteRequestObject) (oapi.CreateRemoteResponseObject, error) {
	body := req.Body
	if body == nil || body.Url == "" {
		return oapi.CreateRemote422JSONResponse(oapi.Error{Error: "url is required"}), nil
	}
	if string(body.Transport) == "" {
		return oapi.CreateRemote422JSONResponse(oapi.Error{Error: "transport is required"}), nil
	}

	normURL, err := git.NormalizeURL(body.Url)
	if err != nil {
		if errors.Is(err, model.ErrBadURL) {
			return oapi.CreateRemote422JSONResponse(oapi.Error{Error: err.Error()}), nil
		}
		return nil, err
	}

	transport := model.Transport(body.Transport)
	switch transport {
	case model.TransportHTTPS, model.TransportSSH:
	default:
		return oapi.CreateRemote422JSONResponse(oapi.Error{Error: "transport must be https or ssh"}), nil
	}

	syncInterval := 5 * time.Minute
	if body.SyncIntervalNs != nil && *body.SyncIntervalNs > 0 {
		syncInterval = time.Duration(*body.SyncIntervalNs)
	}
	if syncInterval < minSyncInterval {
		syncInterval = minSyncInterval // enforce the poll-interval floor
	}
	stalenessBudget := time.Hour
	if body.StalenessBudgetNs != nil && *body.StalenessBudgetNs > 0 {
		stalenessBudget = time.Duration(*body.StalenessBudgetNs)
	}
	taintAnyDeletion := true
	if body.TaintAnyTagDeletion != nil {
		taintAnyDeletion = *body.TaintAnyTagDeletion
	}

	now := s.clock.NowNS()
	r := &model.Remote{
		URL:                 body.Url,
		NormalizedURL:       normURL,
		Transport:           transport,
		SyncInterval:        syncInterval,
		StalenessBudget:     stalenessBudget,
		TaintAnyTagDeletion: taintAnyDeletion,
		Status:              model.RemoteActive,
		ChainHeadHash:       make([]byte, 32), // genesis: 32 zero bytes
		CreatedAtNS:         now,
		UpdatedAtNS:         now,
	}
	id, err := s.store.CreateRemote(ctx, r)
	if err != nil {
		if errors.Is(err, model.ErrConflict) {
			return oapi.CreateRemote409JSONResponse(oapi.Error{Error: "normalized_url already exists"}), nil
		}
		return nil, err
	}
	r.ID = id
	s.log.Info("audit: remote created",
		"op", "createRemote", "principal", principalOf(ctx),
		"remote_id", int64(id), "normalized_url", normURL)
	return oapi.CreateRemote201JSONResponse(remoteToOAPI(*r)), nil
}

// GetRemote implements GET /v1/remotes/{remoteId}.
func (s *StrictServerImpl) GetRemote(ctx context.Context, req oapi.GetRemoteRequestObject) (oapi.GetRemoteResponseObject, error) {
	r, err := s.store.GetRemote(ctx, model.RemoteID(req.RemoteId))
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return oapi.GetRemote404JSONResponse(oapi.Error{Error: "remote not found"}), nil
		}
		return nil, err
	}
	return oapi.GetRemote200JSONResponse(remoteToOAPI(*r)), nil
}

// UpdateRemote implements PATCH /v1/remotes/{remoteId}.
func (s *StrictServerImpl) UpdateRemote(ctx context.Context, req oapi.UpdateRemoteRequestObject) (oapi.UpdateRemoteResponseObject, error) {
	r, err := s.store.GetRemote(ctx, model.RemoteID(req.RemoteId))
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return oapi.UpdateRemote404JSONResponse(oapi.Error{Error: "remote not found"}), nil
		}
		return nil, err
	}

	body := req.Body
	if body == nil {
		return oapi.UpdateRemote200JSONResponse(remoteToOAPI(*r)), nil
	}
	if body.SyncIntervalNs != nil && *body.SyncIntervalNs > 0 {
		r.SyncInterval = time.Duration(*body.SyncIntervalNs)
		if r.SyncInterval < minSyncInterval {
			r.SyncInterval = minSyncInterval // enforce the poll-interval floor
		}
	}
	if body.StalenessBudgetNs != nil && *body.StalenessBudgetNs > 0 {
		r.StalenessBudget = time.Duration(*body.StalenessBudgetNs)
	}
	if body.TaintAnyTagDeletion != nil {
		r.TaintAnyTagDeletion = *body.TaintAnyTagDeletion
	}
	if body.Status != nil {
		r.Status = model.RemoteStatus(string(*body.Status))
	}
	r.UpdatedAtNS = s.clock.NowNS()

	if err := s.store.UpdateRemote(ctx, r); err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return oapi.UpdateRemote404JSONResponse(oapi.Error{Error: "remote not found"}), nil
		}
		return nil, err
	}
	s.log.Info("audit: remote updated",
		"op", "updateRemote", "principal", principalOf(ctx), "remote_id", int64(r.ID))
	return oapi.UpdateRemote200JSONResponse(remoteToOAPI(*r)), nil
}

// DeleteRemote implements DELETE /v1/remotes/{remoteId}.
func (s *StrictServerImpl) DeleteRemote(ctx context.Context, req oapi.DeleteRemoteRequestObject) (oapi.DeleteRemoteResponseObject, error) {
	if _, err := s.store.GetRemote(ctx, model.RemoteID(req.RemoteId)); err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return oapi.DeleteRemote404JSONResponse(oapi.Error{Error: "remote not found"}), nil
		}
		return nil, err
	}
	if err := s.store.SoftDeleteRemote(ctx, model.RemoteID(req.RemoteId), s.clock.NowNS()); err != nil {
		return nil, err
	}
	s.log.Info("audit: remote deleted",
		"op", "deleteRemote", "principal", principalOf(ctx), "remote_id", req.RemoteId)
	return oapi.DeleteRemote204Response{}, nil
}

// ---- Sync ------------------------------------------------------------------

// allowForcedSync enforces the per-remote forced-sync cooldown. It records nowNS
// as the remote's last forced sync and returns false if the previous one was
// within minForcedSyncInterval.
func (s *StrictServerImpl) allowForcedSync(remoteID model.RemoteID, nowNS int64) bool {
	s.forcedMu.Lock()
	defer s.forcedMu.Unlock()
	if last, ok := s.lastForcedNS[remoteID]; ok && nowNS-last < int64(minForcedSyncInterval) {
		return false
	}
	s.lastForcedNS[remoteID] = nowNS
	return true
}

// TriggerSync implements POST /v1/remotes/{remoteId}/sync.
// Confirms the remote exists then fires a background SyncRemote (fire-and-forget).
// The per-remote Lock inside RemoteSyncer prevents overlap with the scheduler.
func (s *StrictServerImpl) TriggerSync(ctx context.Context, req oapi.TriggerSyncRequestObject) (oapi.TriggerSyncResponseObject, error) {
	remoteID := model.RemoteID(req.RemoteId)
	if _, err := s.store.GetRemote(ctx, remoteID); err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return oapi.TriggerSync404JSONResponse(oapi.Error{Error: "remote not found"}), nil
		}
		return nil, err
	}
	if s.syncer != nil && !s.allowForcedSync(remoteID, s.clock.NowNS()) {
		return oapi.TriggerSync429JSONResponse(oapi.Error{Error: "forced sync rate-limited; cooldown not elapsed"}), nil
	}
	s.log.Info("audit: sync triggered",
		"op", "triggerSync", "principal", principalOf(ctx), "remote_id", req.RemoteId)
	if s.syncer != nil {
		go func() { //nolint:gosec // G118: intentional fire-and-forget; the request context must not cancel the sync
			if _, err := s.syncer.SyncRemote(context.Background(), remoteID); err != nil {
				// Best-effort; callers check outcomes via ListSyncs.
				_ = err
			}
		}()
	}
	return oapi.TriggerSync202Response{}, nil
}

// ListSyncs implements GET /v1/remotes/{remoteId}/syncs.
func (s *StrictServerImpl) ListSyncs(ctx context.Context, req oapi.ListSyncsRequestObject) (oapi.ListSyncsResponseObject, error) {
	if _, err := s.store.GetRemote(ctx, model.RemoteID(req.RemoteId)); err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return oapi.ListSyncs404JSONResponse(oapi.Error{Error: "remote not found"}), nil
		}
		return nil, err
	}

	limit := 100
	if req.Params.Limit != nil && *req.Params.Limit > 0 {
		limit = *req.Params.Limit
	}
	if limit > 1000 {
		limit = 1000
	}
	cursor := int64(0)
	if req.Params.Cursor != nil {
		cursor = *req.Params.Cursor
	}

	syncs, nextCursor, err := s.store.ListSyncs(ctx, model.RemoteID(req.RemoteId), limit, cursor)
	if err != nil {
		return nil, err
	}
	items := make([]oapi.SyncEntry, 0, len(syncs))
	for _, sy := range syncs {
		items = append(items, syncToOAPI(sy))
	}
	resp := oapi.SyncAuditList{Items: items}
	if nextCursor > 0 { // omit on the last page (no phantom next cursor)
		resp.NextCursor = &nextCursor
	}
	return oapi.ListSyncs200JSONResponse(resp), nil
}

// ---- Tags ------------------------------------------------------------------

// ListTags implements GET /v1/remotes/{remoteId}/tags.
func (s *StrictServerImpl) ListTags(ctx context.Context, req oapi.ListTagsRequestObject) (oapi.ListTagsResponseObject, error) {
	if _, err := s.store.GetRemote(ctx, model.RemoteID(req.RemoteId)); err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return oapi.ListTags404JSONResponse(oapi.Error{Error: "remote not found"}), nil
		}
		return nil, err
	}
	if req.Params.Q != nil && len(*req.Params.Q) > maxGlobLen {
		return oapi.ListTags422JSONResponse(oapi.Error{Error: "q exceeds 256 bytes"}), nil
	}

	refs, err := s.store.ListTags(ctx, model.RemoteID(req.RemoteId))
	if err != nil {
		return nil, err
	}

	// Apply glob/taint filters in Go (no GLOB pushdown per §9).
	glob := ""
	if req.Params.Q != nil {
		glob = *req.Params.Q
	}
	taintedFilter := "any"
	if req.Params.Tainted != nil {
		taintedFilter = string(*req.Params.Tainted)
	}

	items := make([]oapi.Tag, 0, len(refs))
	for _, r := range refs {
		if glob != "" && !matchGlob(glob, r.TagName) {
			continue
		}
		switch taintedFilter {
		case "only":
			if !r.Tainted {
				continue
			}
		case "never":
			if r.Tainted {
				continue
			}
		}
		items = append(items, tagToOAPI(r))
	}

	// Apply cursor/limit in Go after filtering.
	limit := 100
	if req.Params.Limit != nil && *req.Params.Limit > 0 {
		limit = *req.Params.Limit
	}
	if limit > 1000 {
		limit = 1000
	}
	cursor := int64(0)
	if req.Params.Cursor != nil {
		cursor = *req.Params.Cursor
	}
	// cursor is id-based; filter items with id > cursor.
	filtered := items[:0]
	for _, it := range items {
		if it.Id > cursor {
			filtered = append(filtered, it)
		}
	}
	var nextCursor int64
	if len(filtered) > limit {
		nextCursor = filtered[limit-1].Id
		filtered = filtered[:limit]
	}
	return oapi.ListTags200JSONResponse(oapi.TagList{Items: filtered, NextCursor: &nextCursor}), nil
}

// GetTag implements GET /v1/remotes/{remoteId}/tags/{tagName}.
func (s *StrictServerImpl) GetTag(ctx context.Context, req oapi.GetTagRequestObject) (oapi.GetTagResponseObject, error) {
	if _, err := s.store.GetRemote(ctx, model.RemoteID(req.RemoteId)); err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return oapi.GetTag404JSONResponse(oapi.Error{Error: "remote not found"}), nil
		}
		return nil, err
	}
	if !validTagName(req.TagName) {
		return oapi.GetTag404JSONResponse(oapi.Error{Error: "tag not found"}), nil
	}
	ref, err := s.store.GetRef(ctx, model.RemoteID(req.RemoteId), req.TagName)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return oapi.GetTag404JSONResponse(oapi.Error{Error: "tag not found"}), nil
		}
		return nil, err
	}
	return oapi.GetTag200JSONResponse(tagToOAPI(*ref)), nil
}

// ---- Taint events ----------------------------------------------------------

// ListTaintEvents implements GET /v1/remotes/{remoteId}/taint-events.
func (s *StrictServerImpl) ListTaintEvents(ctx context.Context, req oapi.ListTaintEventsRequestObject) (oapi.ListTaintEventsResponseObject, error) {
	if _, err := s.store.GetRemote(ctx, model.RemoteID(req.RemoteId)); err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return oapi.ListTaintEvents404JSONResponse(oapi.Error{Error: "remote not found"}), nil
		}
		return nil, err
	}

	limit := 100
	if req.Params.Limit != nil && *req.Params.Limit > 0 {
		limit = *req.Params.Limit
	}
	if limit > 1000 {
		limit = 1000
	}
	cursor := int64(0)
	if req.Params.Cursor != nil {
		cursor = *req.Params.Cursor
	}

	events, nextCursor, err := s.store.ListTaintEvents(ctx, model.RemoteID(req.RemoteId), limit, cursor)
	if err != nil {
		return nil, err
	}
	items := make([]oapi.TaintEvent, 0, len(events))
	for _, e := range events {
		items = append(items, taintEventToOAPI(e))
	}
	return oapi.ListTaintEvents200JSONResponse(oapi.TaintEventList{
		Items:      items,
		NextCursor: &nextCursor,
	}), nil
}

// AckTaintEvent implements POST /v1/remotes/{remoteId}/taint-events/{eventId}/ack.
func (s *StrictServerImpl) AckTaintEvent(ctx context.Context, req oapi.AckTaintEventRequestObject) (oapi.AckTaintEventResponseObject, error) {
	if _, err := s.store.GetRemote(ctx, model.RemoteID(req.RemoteId)); err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return oapi.AckTaintEvent404JSONResponse(oapi.Error{Error: "remote not found"}), nil
		}
		return nil, err
	}
	// acked_by defaults to the authenticated principal when the body omits it, so
	// an authenticated operator need not restate their identity. Under auth=none
	// the principal is "anonymous"; the field is therefore always populated and the
	// previous "acked_by is required" rejection no longer occurs.
	principal := principalOf(ctx)
	ackedBy := principal
	if req.Body != nil && req.Body.AckedBy != "" {
		ackedBy = req.Body.AckedBy
	}
	note := ""
	if req.Body != nil && req.Body.AckNote != nil {
		note = *req.Body.AckNote
	}
	if len(ackedBy) > maxAckedByLen || len(note) > maxAckNoteLen {
		return oapi.AckTaintEvent422JSONResponse(oapi.Error{Error: "acked_by must be <=256 and ack_note <=2048 bytes"}), nil
	}
	if err := s.store.AckTaintEvent(ctx, req.EventId, ackedBy, note, s.clock.NowNS()); err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return oapi.AckTaintEvent404JSONResponse(oapi.Error{Error: "taint event not found"}), nil
		}
		if errors.Is(err, model.ErrConflict) {
			return oapi.AckTaintEvent409JSONResponse(oapi.Error{Error: "already acknowledged"}), nil
		}
		return nil, err
	}
	s.log.Info("audit: taint event acked",
		"op", "ackTaintEvent", "principal", principal,
		"remote_id", req.RemoteId, "event_id", req.EventId, "acked_by", ackedBy)
	return oapi.AckTaintEvent204Response{}, nil
}

// ---- Verify ----------------------------------------------------------------

// Operational floors: minSyncInterval is the poll-interval floor (clamped up on
// create/update); minForcedSyncInterval is the per-remote manual-sync cooldown.
const (
	minSyncInterval       = time.Minute
	minForcedSyncInterval = 30 * time.Second
)

// Inline request limits mirroring the OpenAPI request-schema constraints
// (oapi-codegen does not enforce maxLength/pattern, so the handlers do).
const (
	maxRemoteParamLen = 2048
	maxTagNameLen     = 255
	maxAckedByLen     = 256
	maxAckNoteLen     = 2048
	maxGlobLen        = 256
)

// validTagName mirrors the OpenAPI tag/tagName constraints: non-empty, <=255 bytes,
// no control chars or spaces (<=0x20 or 0x7f), and a short name (not a refs/... ref).
func validTagName(s string) bool {
	if s == "" || len(s) > maxTagNameLen || strings.HasPrefix(s, "refs/") {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// reOID accepts 40-hex or 64-hex lowercase.
var reOID = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)

// Verify implements GET /v1/verify.
func (s *StrictServerImpl) Verify(ctx context.Context, req oapi.VerifyRequestObject) (oapi.VerifyResponseObject, error) {
	p := req.Params

	// Validate tag name: short name only, no refs/... prefix, no control chars/spaces, <=255.
	if !validTagName(p.Tag) {
		return oapi.Verify422JSONResponse(oapi.Error{Error: "invalid tag name"}), nil
	}
	if len(p.Remote) > maxRemoteParamLen {
		return oapi.Verify422JSONResponse(oapi.Error{Error: "remote exceeds 2048 bytes"}), nil
	}

	// Validate commit OID if provided.
	var suppliedCommit string
	if p.Commit != nil && *p.Commit != "" {
		c := strings.ToLower(*p.Commit)
		if !reOID.MatchString(c) {
			return oapi.Verify422JSONResponse(oapi.Error{Error: "commit must be 40 or 64 hex chars"}), nil
		}
		suppliedCommit = c
	}

	// Resolve remote: try as id first, then normalized URL.
	remoteParam := p.Remote
	var remote *model.Remote
	if remoteParam == "" {
		return oapi.Verify422JSONResponse(oapi.Error{Error: "remote is required"}), nil
	}

	// Try numeric id.
	if id, err := parseID(remoteParam); err == nil {
		r, err2 := s.store.GetRemote(ctx, model.RemoteID(id))
		if err2 == nil {
			remote = r
		}
	}
	// Try by normalized URL.
	if remote == nil {
		normURL, _ := git.NormalizeURL(remoteParam)
		if normURL == "" {
			normURL = remoteParam
		}
		r, err := s.store.GetRemoteByURL(ctx, normURL)
		if err == nil {
			remote = r
		}
	}

	if remote == nil {
		// not_tracked
		return oapi.Verify200JSONResponse(oapi.VerifyResponse{
			Status:     oapi.VerifyResponseStatusNotTracked,
			Confidence: oapi.Authoritative,
			Tag:        p.Tag,
		}), nil
	}

	remoteInfo := &struct {
		Id            *int64  `json:"id,omitempty"`
		NormalizedUrl *string `json:"normalized_url,omitempty"`
	}{
		Id:            ptr(int64(remote.ID)),
		NormalizedUrl: ptr(remote.NormalizedURL),
	}

	// Determine confidence (stale if last sync old or failed).
	confidence := oapi.Authoritative
	lastSyncedNS := remote.LastOkNS
	syncOutcome := oapi.VerifyResponseSyncOutcomeNever
	if remote.LastOkNS > 0 {
		syncOutcome = oapi.VerifyResponseSyncOutcomeOk
	}
	if remote.ConsecutiveFailures > 0 {
		syncOutcome = oapi.VerifyResponseSyncOutcomeFailed
	}
	if remote.StalenessBudget > 0 && remote.LastOkNS > 0 {
		age := s.clock.NowNS() - remote.LastOkNS // int64-ns span between two timestamps
		if age > int64(remote.StalenessBudget) || remote.ConsecutiveFailures > 0 {
			confidence = oapi.Stale
		}
	} else if remote.LastOkNS == 0 {
		confidence = oapi.Stale
	}

	// Look up the tag.
	ref, err := s.store.GetRef(ctx, remote.ID, p.Tag)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return oapi.Verify200JSONResponse(oapi.VerifyResponse{
				Status:       oapi.VerifyResponseStatusDoesntExist,
				Confidence:   confidence,
				Remote:       remoteInfo,
				Tag:          p.Tag,
				LastSyncedNs: &lastSyncedNS,
				SyncOutcome:  &syncOutcome,
			}), nil
		}
		return nil, err
	}

	// Determine status.
	status := oapi.VerifyResponseStatusOk
	var taintInfo *struct {
		FirstTaintedAtNs *int64  `json:"first_tainted_at_ns,omitempty"`
		FromOid          *string `json:"from_oid,omitempty"`
		Reason           *string `json:"reason,omitempty"`
		ToOid            *string `json:"to_oid,omitempty"`
	}

	if ref.Tainted {
		status = oapi.VerifyResponseStatusTainted
		taintInfo = &struct {
			FirstTaintedAtNs *int64  `json:"first_tainted_at_ns,omitempty"`
			FromOid          *string `json:"from_oid,omitempty"`
			Reason           *string `json:"reason,omitempty"`
			ToOid            *string `json:"to_oid,omitempty"`
		}{
			FirstTaintedAtNs: ref.TaintFirstNS,
		}
	} else if suppliedCommit != "" {
		// Compare against peeled commit oid. CurrentPeeledOID is always set by
		// projectTag for live tags (lightweight: == CurrentOID; annotated: the
		// peeled commit). The fallback to CurrentOID is a belt-and-suspenders guard
		// for any legacy projection rows written before the fix.
		recordedCommit := ""
		if !ref.CurrentPeeledOID.IsZero() {
			recordedCommit = ref.CurrentPeeledOID.Hex()
		} else if !ref.CurrentOID.IsZero() {
			recordedCommit = ref.CurrentOID.Hex()
		}
		if recordedCommit != "" && recordedCommit != suppliedCommit {
			status = oapi.VerifyResponseStatusMismatch
		}
	}

	recorded := &struct {
		FirstSeenNs     *int64  `json:"first_seen_ns,omitempty"`
		LastSeenNs      *int64  `json:"last_seen_ns,omitempty"`
		PeeledCommitOid *string `json:"peeled_commit_oid,omitempty"`
		RefOid          *string `json:"ref_oid,omitempty"`
	}{
		FirstSeenNs: ptr(ref.FirstSeenNS),
		LastSeenNs:  ptr(ref.LastSeenNS),
	}
	if !ref.CurrentOID.IsZero() {
		recorded.RefOid = ptr(ref.CurrentOID.Hex())
	}
	if !ref.CurrentPeeledOID.IsZero() {
		recorded.PeeledCommitOid = ptr(ref.CurrentPeeledOID.Hex())
	}

	resp := oapi.VerifyResponse{
		Status:       status,
		Confidence:   confidence,
		Remote:       remoteInfo,
		Tag:          p.Tag,
		Recorded:     recorded,
		LastSyncedNs: &lastSyncedNS,
		SyncOutcome:  &syncOutcome,
		Taint:        taintInfo,
	}
	if suppliedCommit != "" {
		resp.SuppliedCommit = ptr(suppliedCommit)
	}
	if proof, perr := s.store.LatestObservationForRef(ctx, ref.ID); perr == nil {
		rid := int64(proof.RemoteID)
		sq := int64(proof.Seq)
		rh := fmt.Sprintf("%x", proof.RowHash)
		resp.LedgerProof = &struct {
			RemoteId *int64  `json:"remote_id,omitempty"`
			RowHash  *string `json:"row_hash,omitempty"`
			Seq      *int64  `json:"seq,omitempty"`
		}{RemoteId: &rid, RowHash: &rh, Seq: &sq}
	}
	return oapi.Verify200JSONResponse(resp), nil
}

// ---- Convert helpers -------------------------------------------------------

func remoteToOAPI(r model.Remote) oapi.Remote {
	or := oapi.Remote{
		Id:                  int64(r.ID),
		Url:                 r.URL,
		NormalizedUrl:       r.NormalizedURL,
		Transport:           oapi.RemoteTransport(r.Transport),
		SyncIntervalNs:      int64(r.SyncInterval),
		StalenessBudgetNs:   int64(r.StalenessBudget),
		TaintAnyTagDeletion: r.TaintAnyTagDeletion,
		Status:              oapi.RemoteStatus(r.Status),
		LastOkNs:            r.LastOkNS,
		LastErr:             r.LastErr,
		ConsecutiveFailures: r.ConsecutiveFailures,
		ChainLen:            r.ChainLen,
		CreatedAtNs:         r.CreatedAtNS,
		UpdatedAtNs:         r.UpdatedAtNS,
	}
	if r.HashAlgo != nil {
		ha := oapi.RemoteHashAlgo(*r.HashAlgo)
		or.HashAlgo = &ha
	}
	if r.RemovedAtNS != nil {
		v := *r.RemovedAtNS
		or.RemovedAtNs = &v
	}
	return or
}

func tagToOAPI(r model.Ref) oapi.Tag {
	t := oapi.Tag{
		Id:               int64(r.ID),
		RemoteId:         int64(r.RemoteID),
		TagName:          r.TagName,
		Deleted:          r.Deleted,
		Tainted:          r.Tainted,
		FirstSeenNs:      r.FirstSeenNS,
		LastSeenNs:       r.LastSeenNS,
		LastChangedNs:    &r.LastChangedNS,
		ObservationCount: r.ObservationCount,
	}
	ia := r.IsAnnotatedTag
	t.IsAnnotated = &ia
	if !r.CurrentOID.IsZero() {
		s := r.CurrentOID.Hex()
		t.CurrentOid = &s
	}
	if !r.CurrentPeeledOID.IsZero() {
		s := r.CurrentPeeledOID.Hex()
		t.CurrentPeeledOid = &s
	}
	if !r.FirstOID.IsZero() {
		s := r.FirstOID.Hex()
		t.FirstOid = &s
	}
	if r.TaintFirstNS != nil {
		t.TaintFirstNs = r.TaintFirstNS
	}
	return t
}

func syncToOAPI(s model.Sync) oapi.SyncEntry {
	e := oapi.SyncEntry{
		Id:          int64(s.ID),
		RemoteId:    int64(s.RemoteID),
		Trigger:     oapi.SyncEntryTrigger(s.Trigger),
		StartedNs:   s.StartedNS,
		FinishedNs:  s.FinishedNS,
		Status:      oapi.SyncEntryStatus(s.Status),
		TagsSeen:    int(s.TagsSeen),
		TagsChanged: int(s.TagsChanged),
	}
	if s.Error != "" {
		e.Error = ptr(s.Error)
	}
	if len(s.ChainHeadBefore) > 0 {
		e.ChainHeadBefore = ptr(hex.EncodeToString(s.ChainHeadBefore))
	}
	if len(s.ChainHeadAfter) > 0 {
		e.ChainHeadAfter = ptr(hex.EncodeToString(s.ChainHeadAfter))
	}
	return e
}

func taintEventToOAPI(e model.TaintEvent) oapi.TaintEvent {
	te := oapi.TaintEvent{
		Id:           e.ID,
		RemoteId:     int64(e.RemoteID),
		RefId:        int64(e.RefID),
		Reason:       oapi.TaintEventReason(e.Reason),
		DetectedAtNs: e.DetectedAtNS,
		Detail:       ptr(e.Detail),
	}
	if e.ObservationID != nil {
		te.ObservationId = e.ObservationID
	}
	if !e.FromOID.IsZero() {
		s := e.FromOID.Hex()
		te.FromOid = &s
	}
	if !e.ToOID.IsZero() {
		s := e.ToOID.Hex()
		te.ToOid = &s
	}
	if e.AckedAtNS != nil {
		te.AckedAtNs = e.AckedAtNS
	}
	if e.AckedBy != "" {
		te.AckedBy = ptr(e.AckedBy)
	}
	if e.AckNote != "" {
		te.AckNote = ptr(e.AckNote)
	}
	return te
}

// matchGlob implements simple glob matching (* = any run of non-separator chars).
func matchGlob(pattern, name string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	// Simple implementation: convert glob to segments and match.
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return name == pattern
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]
	for _, p := range parts[1 : len(parts)-1] {
		idx := strings.Index(name, p)
		if idx < 0 {
			return false
		}
		name = name[idx+len(p):]
	}
	return strings.HasSuffix(name, parts[len(parts)-1])
}

func parseID(s string) (int64, error) {
	var id int64
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, errors.New("not a numeric id")
		}
		id = id*10 + int64(ch-'0')
	}
	if len(s) == 0 {
		return 0, errors.New("empty")
	}
	return id, nil
}

func ptr[T any](v T) *T { return &v }
