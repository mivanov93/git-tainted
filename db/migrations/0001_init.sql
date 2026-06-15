-- 0001_init.sql — git-tainted §9 schema.
-- Forward-only; no down migration. Applied at startup by internal/store/migrate.go.
-- All timestamps: BIGINT unix-nanoseconds. All oids: BLOB (sha1=20B, sha256=32B raw).
-- hex<->raw conversion is centralized in internal/store/store.go, not in SQL.

-- Migration bookkeeping (applied by migrate.go before domain rows below).
-- NOTE: PRAGMA journal_mode=WAL and PRAGMA foreign_keys=ON are set by
-- store.Open() outside of any transaction and must NOT appear here.
CREATE TABLE IF NOT EXISTS schema_migrations (
  version       INTEGER PRIMARY KEY,
  applied_at_ns BIGINT  NOT NULL
);

-- -------------------------------------------------------------------------
-- remotes: the top entity — git remote URLs we poll for tags.
-- chain_head_hash genesis = 32 zero bytes (set in code at insert time).
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remotes (
  id                      INTEGER PRIMARY KEY AUTOINCREMENT,
  url                     TEXT    NOT NULL,
  normalized_url          TEXT    NOT NULL UNIQUE,
  transport               TEXT    NOT NULL
                            CHECK (transport IN ('https','ssh')),
  sync_interval_ns        BIGINT  NOT NULL DEFAULT 300000000000,
  staleness_budget_ns     BIGINT  NOT NULL DEFAULT 0,
  taint_any_tag_deletion  INT     NOT NULL DEFAULT 1,
  hash_algo               TEXT    NULL
                            CHECK (hash_algo IS NULL OR hash_algo IN ('sha1','sha256')),
  status                  TEXT    NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active','degraded','paused')),
  last_ok_ns              BIGINT  NOT NULL DEFAULT 0,
  last_err                TEXT    NOT NULL DEFAULT '',
  consecutive_failures    INT     NOT NULL DEFAULT 0,
  chain_head_hash         BLOB    NOT NULL,
  chain_len               BIGINT  NOT NULL DEFAULT 0,
  removed_at_ns           BIGINT  NULL,
  created_at_ns           BIGINT  NOT NULL,
  updated_at_ns           BIGINT  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_remotes_active
  ON remotes (status)
  WHERE removed_at_ns IS NULL;

-- -------------------------------------------------------------------------
-- refs: tags only; per-remote projection, rebuildable from observations.
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refs (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  remote_id           INTEGER NOT NULL REFERENCES remotes(id),
  tag_name            TEXT    NOT NULL,
  current_oid         BLOB    NULL,
  current_peeled_oid  BLOB    NULL,
  is_annotated        INT     NOT NULL DEFAULT 0,
  first_oid           BLOB    NULL,
  first_seen_ns       BIGINT  NOT NULL DEFAULT 0,
  last_seen_ns        BIGINT  NOT NULL DEFAULT 0,
  last_changed_ns     BIGINT  NOT NULL DEFAULT 0,
  deleted             INT     NOT NULL DEFAULT 0,
  tainted             INT     NOT NULL DEFAULT 0,
  taint_first_ns      BIGINT  NULL,
  observation_count   BIGINT  NOT NULL DEFAULT 0,
  UNIQUE (remote_id, tag_name)
);
CREATE INDEX IF NOT EXISTS idx_refs_remote
  ON refs (remote_id);

-- -------------------------------------------------------------------------
-- syncs: run audit log.
-- Declared before observations because observations.sync_id FK references it.
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS syncs (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  remote_id        INTEGER NOT NULL REFERENCES remotes(id),
  trigger          TEXT    NOT NULL DEFAULT 'scheduled'
                     CHECK (trigger IN ('register','scheduled','manual')),
  started_ns       BIGINT  NOT NULL DEFAULT 0,
  finished_ns      BIGINT  NOT NULL DEFAULT 0,
  status           TEXT    NOT NULL DEFAULT 'failed'
                     CHECK (status IN ('ok','partial','failed')),
  tags_seen        INT     NOT NULL DEFAULT 0,
  tags_changed     INT     NOT NULL DEFAULT 0,
  error            TEXT    NOT NULL DEFAULT '',
  chain_head_before BLOB   NULL,
  chain_head_after  BLOB   NULL
);

-- -------------------------------------------------------------------------
-- observations: APPEND-ONLY per-remote hash-chained ledger. NO UPDATE/DELETE.
-- row_hash = SHA-256(prev_hash || canonical(row))
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS observations (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  remote_id       INTEGER NOT NULL REFERENCES remotes(id),
  ref_id          INTEGER NOT NULL REFERENCES refs(id),
  sync_id         INTEGER NOT NULL REFERENCES syncs(id) DEFERRABLE INITIALLY DEFERRED,
  seq             BIGINT  NOT NULL,
  event_type      TEXT    NOT NULL
                    CHECK (event_type IN (
                      'tag_created','tag_oid_changed','tag_deleted','tag_recreated'
                    )),
  prev_oid        BLOB    NULL,
  new_oid         BLOB    NULL,
  prev_peeled_oid BLOB    NULL,
  new_peeled_oid  BLOB    NULL,
  observed_at_ns  BIGINT  NOT NULL,
  prev_hash       BLOB    NOT NULL,
  row_hash        BLOB    NOT NULL,
  canonical_meta  TEXT    NULL,
  UNIQUE (remote_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_observations_ref_ts
  ON observations (ref_id, observed_at_ns DESC);

-- -------------------------------------------------------------------------
-- taint_events: IMMUTABLE taint spine.
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS taint_events (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  remote_id        INTEGER NOT NULL REFERENCES remotes(id),
  ref_id           INTEGER NOT NULL REFERENCES refs(id),
  reason           TEXT    NOT NULL
                     CHECK (reason IN ('tag_oid_changed','tag_deleted_recreated')),
  observation_id   INTEGER NULL     REFERENCES observations(id),
  from_oid         BLOB    NULL,
  to_oid           BLOB    NULL,
  detected_at_ns   BIGINT  NOT NULL,
  acked_at_ns      BIGINT  NULL,
  acked_by         TEXT    NULL,
  ack_note         TEXT    NULL,
  detail           TEXT    NOT NULL DEFAULT '',
  UNIQUE (remote_id, ref_id, reason, from_oid, to_oid)
);

-- -------------------------------------------------------------------------
-- remote_lease: Lock seam — DB-backed per-remote writer lease.
-- PK is remote_id (one active lease per remote at a time).
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remote_lease (
  remote_id      INTEGER PRIMARY KEY REFERENCES remotes(id),
  holder         TEXT   NOT NULL,
  acquired_at_ns BIGINT NOT NULL,
  expires_at_ns  BIGINT NOT NULL
);
