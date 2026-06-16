-- InsertTaintEvent is idempotent on the unique key (remote_id, ref_id, reason,
-- from_oid, to_oid). MySQL has no RETURNING; the store reads the id back via
-- GetTaintEventID using the same unique key. The ON DUPLICATE KEY UPDATE is a
-- self-assignment no-op that preserves the original detected_at_ns.
-- name: InsertTaintEvent :execlastid
INSERT INTO taint_events (
  remote_id, ref_id, reason,
  observation_id, from_oid, to_oid,
  detected_at_ns, detail
) VALUES (?,?,?,?,?,?,?,?)
ON DUPLICATE KEY UPDATE detected_at_ns = detected_at_ns;

-- name: GetTaintEventID :one
SELECT id FROM taint_events
WHERE remote_id = ? AND ref_id = ? AND reason = ?
  AND from_oid <=> ? AND to_oid <=> ?
LIMIT 1;

-- name: ListTaintEvents :many
SELECT id, remote_id, ref_id, reason,
       observation_id, from_oid, to_oid,
       detected_at_ns, acked_at_ns, acked_by, ack_note, detail
FROM taint_events
WHERE remote_id = ? AND id > ?
ORDER BY id ASC
LIMIT ?;

-- name: AckTaintEvent :exec
UPDATE taint_events
SET acked_at_ns = ?, acked_by = ?, ack_note = ?
WHERE id = ? AND acked_at_ns IS NULL;
