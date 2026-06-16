package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/mivanov93/git-tainted/internal/model"
)

// SyncResult summarizes one per-remote sync (mirrors the syncs audit row).
type SyncResult struct {
	SyncID      model.SyncID
	Status      model.SyncStatus
	TagsSeen    int
	TagsChanged int
	HeadBefore  []byte
	HeadAfter   []byte
}

// syncStore is the subset of model.Store the RemoteSyncer uses.
type syncStore interface {
	model.RemoteStore
	model.RefStore
	model.ObservationStore
	model.TaintStore
	model.SyncStore
	model.LeaseStore
	WithTx(ctx context.Context, fn func(ctx context.Context, tx model.Tx) error) error
}

// RemoteSyncer runs the per-remote ls-remote sync path (§6).
type RemoteSyncer struct {
	store  syncStore
	git    model.GitRunner
	lock   model.Lock
	clk    model.Clock
	holder string
}

// NewRemoteSyncer constructs the per-remote syncer. holder is this instance id.
func NewRemoteSyncer(store syncStore, git model.GitRunner, lk model.Lock, clk model.Clock, holder string) *RemoteSyncer {
	return &RemoteSyncer{store: store, git: git, lock: lk, clk: clk, holder: holder}
}

// leaseTTL bounds a sync's writer lease (2 minutes).
const leaseTTL = 2 * time.Minute

// SyncRemote performs one ls-remote-path sync for a remote (§6).
func (rs *RemoteSyncer) SyncRemote(ctx context.Context, remoteID model.RemoteID) (*SyncResult, error) {
	r, err := rs.store.GetRemote(ctx, remoteID)
	if err != nil {
		return nil, fmt.Errorf("get remote: %w", err)
	}

	lease, err := rs.lock.AcquireRemoteLease(ctx, remoteID, rs.holder, leaseTTL)
	if err != nil {
		return nil, fmt.Errorf("acquire lease: %w", err)
	}

	startNS := rs.clk.NowNS()
	headBefore := append([]byte(nil), lease.ChainHeadAtLease...)

	// §6 step 1: ls-remote --tags (hardened)
	lsRefs, lsErr := rs.git.LsRemote(ctx, r.URL, nil)
	if lsErr != nil {
		_ = rs.store.SetRemoteHealth(ctx, remoteID, model.RemoteDegraded, lsErr.Error(), startNS)
		_ = rs.lock.Release(ctx, lease, headBefore, r.ChainLen)
		return &SyncResult{Status: model.SyncFailed, HeadBefore: headBefore, HeadAfter: headBefore},
			fmt.Errorf("ls-remote: %w", lsErr)
	}

	// Load prior projection (all tags including deleted).
	prior, err := rs.store.ListTags(ctx, remoteID)
	if err != nil {
		_ = rs.lock.Release(ctx, lease, headBefore, r.ChainLen)
		return nil, fmt.Errorf("list tags: %w", err)
	}
	priorByName := map[string]*model.Ref{}
	for i := range prior {
		priorByName[prior[i].TagName] = &prior[i]
	}
	seenName := map[string]bool{}

	var result SyncResult
	result.HeadBefore = headBefore
	result.TagsSeen = len(lsRefs)

	txErr := rs.store.WithTx(ctx, func(ctx context.Context, tx model.Tx) error {
		nowNS := rs.clk.NowNS()
		syncID, err := tx.WriteSync(ctx, &model.Sync{
			RemoteID:        remoteID,
			Trigger:         model.TriggerScheduled,
			StartedNS:       startNS,
			FinishedNS:      nowNS,
			Status:          model.SyncOk,
			TagsSeen:        len(lsRefs),
			ChainHeadBefore: headBefore,
		})
		if err != nil {
			return fmt.Errorf("write sync: %w", err)
		}
		result.SyncID = syncID

		for i := range lsRefs {
			now := &lsRefs[i]
			seenName[string(now.Name)] = true
			prev := priorByName[string(now.Name)]

			delta := ClassifyTag(prev, now)
			ref := projectTag(prev, now, nowNS, remoteID)
			if err := tx.UpsertRefProjection(ctx, ref); err != nil {
				return fmt.Errorf("upsert ref %s: %w", now.Name, err)
			}
			if delta.Event == "" {
				continue // no change — no observation
			}
			obs := &model.Observation{
				RemoteID:     remoteID,
				RefID:        ref.ID,
				SyncID:       syncID,
				EventType:    delta.Event,
				NewOID:       now.OID,
				NewPeeledOID: now.PeeledOID,
				ObservedAtNS: nowNS,
			}
			if prev != nil && !prev.CurrentOID.IsZero() {
				obs.PrevOID = prev.CurrentOID
				obs.PrevPeeledOID = prev.CurrentPeeledOID
			}
			if _, err := tx.AppendObservation(ctx, obs); err != nil {
				return fmt.Errorf("append obs %s: %w", now.Name, err)
			}
			result.TagsChanged++
			if delta.Taint != nil {
				if err := applyTaint(ctx, tx, remoteID, ref, obs.PrevOID, now.OID, *delta.Taint, obs.ID, nowNS); err != nil {
					return err
				}
			}
		}

		// §6 step 4: deletions — prior tags absent from this ls-remote
		for name, prev := range priorByName {
			if seenName[name] || prev.Deleted {
				continue
			}
			nowNS2 := rs.clk.NowNS()
			delta := ClassifyDeletion(prev, r.TaintAnyTagDeletion)
			prev.Deleted = true
			prev.LastSeenNS = nowNS2
			if err := tx.UpsertRefProjection(ctx, prev); err != nil {
				return err
			}
			obs := &model.Observation{
				RemoteID:      remoteID,
				RefID:         prev.ID,
				SyncID:        syncID,
				EventType:     delta.Event,
				PrevOID:       prev.CurrentOID,
				PrevPeeledOID: prev.CurrentPeeledOID,
				ObservedAtNS:  nowNS2,
			}
			if _, err := tx.AppendObservation(ctx, obs); err != nil {
				return err
			}
			result.TagsChanged++
			if delta.Taint != nil {
				if err := applyTaint(ctx, tx, remoteID, prev, prev.CurrentOID, model.OID{}, *delta.Taint, obs.ID, nowNS2); err != nil {
					return err
				}
			}
		}
		return nil
	})

	if txErr != nil {
		_ = rs.lock.Release(ctx, lease, headBefore, r.ChainLen)
		_ = rs.store.SetRemoteHealth(ctx, remoteID, model.RemoteDegraded, txErr.Error(), rs.clk.NowNS())
		return &SyncResult{Status: model.SyncFailed, HeadBefore: headBefore, HeadAfter: headBefore}, txErr
	}

	headAfter, newLen, err := rs.store.GetChainHead(ctx, remoteID)
	if err != nil {
		return nil, fmt.Errorf("read chain head: %w", err)
	}
	if err := rs.lock.Release(ctx, lease, headAfter, newLen); err != nil {
		return nil, fmt.Errorf("release lease: %w", err)
	}
	_ = rs.store.SetRemoteHealth(ctx, remoteID, model.RemoteActive, "", rs.clk.NowNS())

	result.Status = model.SyncOk
	result.HeadAfter = headAfter
	return &result, nil
}

// projectTag builds the updated refs projection from the prior row (if any)
// and the fresh ls-remote ref.
func projectTag(prev *model.Ref, now *model.LsRemoteRef, nowNS int64, remoteID model.RemoteID) *model.Ref {
	// For a lightweight tag PeeledOID is zero (ls-remote emits no ^{} line).
	// A lightweight tag points directly to the commit, so its effective peeled
	// OID is the tag OID itself. Normalise here so CurrentPeeledOID always
	// carries the commit a checkout lands on, across both lightweight and
	// annotated tags.
	peeledOID := now.PeeledOID
	if peeledOID.IsZero() {
		peeledOID = now.OID
	}
	ref := &model.Ref{
		RemoteID:         remoteID,
		TagName:          string(now.Name),
		CurrentOID:       now.OID,
		CurrentPeeledOID: peeledOID,
		IsAnnotatedTag:   now.IsAnnotatedTag,
		LastSeenNS:       nowNS,
	}
	if prev == nil {
		ref.FirstOID = now.OID
		ref.FirstSeenNS = nowNS
		ref.LastChangedNS = nowNS
		ref.ObservationCount = 1
		return ref
	}
	ref.ID = prev.ID
	ref.RemoteID = prev.RemoteID
	ref.FirstOID = prev.FirstOID
	ref.FirstSeenNS = prev.FirstSeenNS
	ref.Tainted = prev.Tainted
	ref.TaintFirstNS = prev.TaintFirstNS
	ref.ObservationCount = prev.ObservationCount + 1
	ref.LastChangedNS = prev.LastChangedNS
	if !now.OID.Equal(prev.CurrentOID) {
		ref.LastChangedNS = nowNS
	}
	return ref
}

// applyTaint flips refs.tainted (sticky) and appends an immutable taint_events row.
func applyTaint(ctx context.Context, tx model.Tx, remoteID model.RemoteID, ref *model.Ref, fromOID, toOID model.OID, reason model.TaintReason, obsID int64, nowNS int64) error {
	if ref.TaintFirstNS == nil {
		ref.Tainted = true
		ref.TaintFirstNS = &nowNS
		if err := tx.UpsertRefProjection(ctx, ref); err != nil {
			return fmt.Errorf("set ref taint: %w", err)
		}
	}
	e := &model.TaintEvent{
		RemoteID:      remoteID,
		RefID:         ref.ID,
		Reason:        reason,
		ObservationID: &obsID,
		FromOID:       fromOID,
		ToOID:         toOID,
		DetectedAtNS:  nowNS,
	}
	if _, err := tx.AppendTaintEvent(ctx, e); err != nil {
		return fmt.Errorf("append taint_event: %w", err)
	}
	return nil
}
