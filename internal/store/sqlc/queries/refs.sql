-- name: GetRef :one
SELECT * FROM refs
WHERE remote_id = ? AND tag_name = ?
LIMIT 1;

-- name: ListTags :many
SELECT * FROM refs
WHERE remote_id = ?
ORDER BY tag_name ASC;

-- name: UpsertRef :one
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
ON CONFLICT (remote_id, tag_name) DO UPDATE SET
  current_oid        = excluded.current_oid,
  current_peeled_oid = excluded.current_peeled_oid,
  is_annotated       = excluded.is_annotated,
  last_seen_ns       = excluded.last_seen_ns,
  last_changed_ns    = excluded.last_changed_ns,
  deleted            = excluded.deleted,
  tainted            = excluded.tainted,
  taint_first_ns     = excluded.taint_first_ns,
  observation_count  = excluded.observation_count
RETURNING *;

-- name: SetRefTaint :exec
UPDATE refs SET tainted = 1, taint_first_ns = ?
WHERE id = ?;

-- name: CountRefs :one
SELECT COUNT(*) FROM refs WHERE remote_id = ?;
