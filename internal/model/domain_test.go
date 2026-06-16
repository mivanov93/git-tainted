package model

import "testing"

func TestDomainStructsCompile(t *testing.T) {
	// Compile-time proof: all domain structs can be zero-constructed and their
	// fields accessed. If a field name or type is wrong, this file fails to compile.

	var r Remote
	_ = r.ID
	_ = r.URL
	_ = r.NormalizedURL
	_ = r.Transport
	_ = r.SyncInterval
	_ = r.StalenessBudget
	_ = r.TaintAnyTagDeletion
	_ = r.HashAlgo // *HashAlgo
	_ = r.Status
	_ = r.LastOkNS
	_ = r.LastErr
	_ = r.ConsecutiveFailures
	_ = r.ChainHeadHash
	_ = r.ChainLen
	_ = r.RemovedAtNS // *int64
	_ = r.CreatedAtNS
	_ = r.UpdatedAtNS

	var ref Ref
	_ = ref.ID
	_ = ref.RemoteID
	_ = ref.TagName
	_ = ref.CurrentOID       // OID
	_ = ref.CurrentPeeledOID // OID
	_ = ref.IsAnnotatedTag
	_ = ref.FirstOID
	_ = ref.FirstSeenNS
	_ = ref.LastSeenNS
	_ = ref.LastChangedNS
	_ = ref.Deleted
	_ = ref.Tainted
	_ = ref.TaintFirstNS // *int64
	_ = ref.ObservationCount

	var obs Observation
	_ = obs.ID
	_ = obs.RemoteID
	_ = obs.RefID
	_ = obs.SyncID
	_ = obs.Seq
	_ = obs.EventType
	_ = obs.PrevOID
	_ = obs.NewOID
	_ = obs.PrevPeeledOID
	_ = obs.NewPeeledOID
	_ = obs.ObservedAtNS
	_ = obs.PrevHash
	_ = obs.RowHash
	_ = obs.CanonicalMeta

	var te TaintEvent
	_ = te.ID
	_ = te.RemoteID
	_ = te.RefID
	_ = te.Reason
	_ = te.ObservationID // *int64
	_ = te.FromOID
	_ = te.ToOID
	_ = te.DetectedAtNS
	_ = te.AckedAtNS // *int64
	_ = te.AckedBy
	_ = te.AckNote
	_ = te.Detail

	var s Sync
	_ = s.ID
	_ = s.RemoteID
	_ = s.Trigger
	_ = s.StartedNS
	_ = s.FinishedNS
	_ = s.Status
	_ = s.TagsSeen
	_ = s.TagsChanged
	_ = s.Error
	_ = s.ChainHeadBefore
	_ = s.ChainHeadAfter
}
