-- name: InsertObservation :execlastid
INSERT INTO observations (
  remote_id, ref_id, sync_id, seq, event_type,
  prev_oid, new_oid, prev_peeled_oid, new_peeled_oid,
  observed_at_ns, prev_hash, row_hash, canonical_meta
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);

-- name: GetRemoteChainHeadObs :one
SELECT chain_head_hash, chain_len FROM remotes WHERE id = ?;

-- name: ReplayObservations :many
SELECT id, remote_id, ref_id, sync_id, seq, event_type,
       prev_oid, new_oid, prev_peeled_oid, new_peeled_oid,
       observed_at_ns, prev_hash, row_hash, canonical_meta
FROM observations
WHERE remote_id = ? AND seq > ?
ORDER BY seq ASC
LIMIT ?;

-- name: LatestObservationForRef :one
SELECT remote_id, seq, row_hash
FROM observations
WHERE ref_id = ?
ORDER BY seq DESC
LIMIT 1;
