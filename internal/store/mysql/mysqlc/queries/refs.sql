-- name: GetRef :one
SELECT * FROM refs
WHERE remote_id = ? AND tag_name = ?
LIMIT 1;

-- name: ListTags :many
SELECT * FROM refs
WHERE remote_id = ?
ORDER BY tag_name ASC;

-- UpsertRef has no RETURNING in MySQL: INSERT ... ON DUPLICATE KEY UPDATE,
-- then the store reads the id back via GetRefIDByName (unique key remote_id,tag_name).
-- name: UpsertRef :exec
INSERT INTO refs (
  remote_id, tag_name,
  current_oid, current_peeled_oid, is_annotated,
  first_oid, first_seen_ns, last_seen_ns, last_changed_ns,
  deleted, tainted, taint_first_ns,
  observation_count
) VALUES (
  ?, ?,
  ?, ?, ?,
  ?, ?, ?, ?,
  ?, ?, ?,
  ?
)
ON DUPLICATE KEY UPDATE
  current_oid        = VALUES(current_oid),
  current_peeled_oid = VALUES(current_peeled_oid),
  is_annotated       = VALUES(is_annotated),
  last_seen_ns       = VALUES(last_seen_ns),
  last_changed_ns    = VALUES(last_changed_ns),
  deleted            = VALUES(deleted),
  tainted            = VALUES(tainted),
  taint_first_ns     = VALUES(taint_first_ns),
  observation_count  = VALUES(observation_count);

-- name: GetRefIDByName :one
SELECT id, remote_id FROM refs WHERE remote_id = ? AND tag_name = ? LIMIT 1;

-- name: SetRefTaint :exec
UPDATE refs SET tainted = 1, taint_first_ns = ?
WHERE id = ?;

-- name: CountRefs :one
SELECT COUNT(*) FROM refs WHERE remote_id = ?;
