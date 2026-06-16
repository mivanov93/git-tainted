-- trigger is a MySQL reserved word → backticked.

-- name: InsertSync :execlastid
INSERT INTO syncs (
  remote_id, `trigger`, started_ns, finished_ns, status,
  tags_seen, tags_changed, error, chain_head_before, chain_head_after
) VALUES (?,?,?,?,?,?,?,?,?,?);

-- name: ListSyncs :many
SELECT * FROM syncs
WHERE remote_id = ? AND id > ?
ORDER BY id DESC
LIMIT ?;
