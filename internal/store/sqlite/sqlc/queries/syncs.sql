-- name: InsertSync :one
INSERT INTO syncs (
  remote_id, trigger, started_ns, finished_ns, status,
  tags_seen, tags_changed, error, chain_head_before, chain_head_after
) VALUES (?,?,?,?,?,?,?,?,?,?)
RETURNING id;

-- name: ListSyncs :many
SELECT * FROM syncs
WHERE remote_id = ? AND id < ?
ORDER BY id DESC
LIMIT ?;

-- name: PruneSyncs :exec
DELETE FROM syncs WHERE syncs.remote_id = ?
  AND syncs.id NOT IN (SELECT id FROM (SELECT id FROM syncs s WHERE s.remote_id = ? ORDER BY id DESC LIMIT ?) AS keep_ids)
  AND syncs.id NOT IN (SELECT sync_id FROM observations o WHERE o.remote_id = ?);
