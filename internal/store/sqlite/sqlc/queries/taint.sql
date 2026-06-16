-- name: InsertTaintEvent :one
INSERT INTO taint_events (
  remote_id, ref_id, reason,
  observation_id, from_oid, to_oid,
  detected_at_ns, detail
) VALUES (?,?,?,?,?,?,?,?)
ON CONFLICT (remote_id, ref_id, reason, from_oid, to_oid)
DO UPDATE SET detected_at_ns = detected_at_ns  -- idempotent; keep original
RETURNING id;

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
