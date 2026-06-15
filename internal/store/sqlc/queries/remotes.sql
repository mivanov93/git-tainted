-- name: CreateRemote :one
INSERT INTO remotes (
  url, normalized_url, transport,
  sync_interval_ns, staleness_budget_ns, taint_any_tag_deletion,
  hash_algo, status, last_ok_ns, last_err, consecutive_failures,
  chain_head_hash, chain_len, removed_at_ns, created_at_ns, updated_at_ns
) VALUES (
  ?, ?, ?,
  ?, ?, ?,
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?
)
RETURNING *;

-- name: GetRemote :one
SELECT * FROM remotes WHERE id = ? LIMIT 1;

-- name: GetRemoteByURL :one
SELECT * FROM remotes WHERE normalized_url = ? AND removed_at_ns IS NULL LIMIT 1;

-- name: ListRemotes :many
SELECT * FROM remotes
WHERE id > ?
ORDER BY id ASC
LIMIT ?;

-- name: UpdateRemote :one
UPDATE remotes SET
  url                    = ?,
  normalized_url         = ?,
  transport              = ?,
  sync_interval_ns       = ?,
  staleness_budget_ns    = ?,
  taint_any_tag_deletion = ?,
  hash_algo              = ?,
  status                 = ?,
  last_ok_ns             = ?,
  last_err               = ?,
  consecutive_failures   = ?,
  chain_head_hash        = ?,
  chain_len              = ?,
  removed_at_ns          = ?,
  updated_at_ns          = ?
WHERE id = ?
RETURNING *;

-- name: SoftDeleteRemote :exec
UPDATE remotes SET removed_at_ns = ?, updated_at_ns = ? WHERE id = ?;

-- name: SetRemoteHealth :exec
UPDATE remotes SET status = ?, last_err = ?, last_ok_ns = ?, updated_at_ns = ?
WHERE id = ?;

-- name: SelectDueRemotes :many
-- Returns active, non-removed remotes whose next sync time has passed.
-- last_ok_ns + sync_interval_ns < nowNS
SELECT * FROM remotes
WHERE status = 'active'
  AND removed_at_ns IS NULL
  AND (last_ok_ns + sync_interval_ns) < ?
ORDER BY (last_ok_ns + sync_interval_ns) ASC
LIMIT ?;

-- name: GetChainHead :one
SELECT chain_head_hash, chain_len FROM remotes WHERE id = ? LIMIT 1;

-- name: GetRemoteChainHead :one
SELECT chain_head_hash, chain_len FROM remotes WHERE id = ?;

-- name: AdvanceChainHead :exec
UPDATE remotes SET chain_head_hash = ?, chain_len = ?
WHERE id = ?;

-- name: AdvanceRemoteChainHead :execrows
UPDATE remotes
SET chain_head_hash = ?, chain_len = ?
WHERE id = ? AND chain_head_hash = ? AND chain_len = ?;
