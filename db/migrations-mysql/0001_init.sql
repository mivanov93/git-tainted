-- 0001_init.sql (MySQL 8) — git-tainted §9 schema, MySQL 8.x dialect.
-- Second Store implementation; mirrors db/migrations/0001_init.sql (SQLite) exactly
-- in columns, UNIQUE keys, indexes, FKs, and CHECK constraints (MySQL 8 enforces CHECK).
--
-- Dialect mapping vs the SQLite schema:
--   * ENGINE=InnoDB on every table (transactions + FK enforcement).
--   * Surrogate ids: BIGINT AUTO_INCREMENT PRIMARY KEY (vs INTEGER PRIMARY KEY AUTOINCREMENT).
--   * oids / hashes: VARBINARY(32) — raw bytes (sha1=20B, sha256=32B); chain hashes are 32B.
--   * All timestamps: BIGINT unix-nanoseconds (never DATETIME).
--   * Partial index `WHERE removed_at_ns IS NULL` (SQLite) has no MySQL equivalent →
--     a plain index on (status); the removed_at_ns predicate stays in the query.
--   * SQLite `DEFERRABLE INITIALLY DEFERRED` on observations.sync_id is not a MySQL
--     concept; FK checks in InnoDB are per-statement and the write path inserts the
--     syncs row before the observation in the same txn, so no deferral is needed.
--   * Every table uses CREATE TABLE IF NOT EXISTS: MySQL DDL auto-commits, so a re-run
--     after a partial failure must be idempotent.
-- hex<->raw oid conversion is centralized in internal/store, not in SQL.

-- Migration bookkeeping (compatible with internal/store/migrate.go).
-- version is INT PRIMARY KEY (no AUTO_INCREMENT: the runner supplies the value).
CREATE TABLE IF NOT EXISTS schema_migrations (
  version       INT    NOT NULL,
  applied_at_ns BIGINT NOT NULL,
  PRIMARY KEY (version)
) ENGINE=InnoDB;

-- -------------------------------------------------------------------------
-- remotes: the top entity — git remote URLs we poll for tags.
-- chain_head_hash genesis = 32 zero bytes (set in code at insert time).
-- normalized_url is the UNIQUE business key; VARCHAR(768) keeps it within the
-- InnoDB utf8mb4 index-prefix limit (768*4 = 3072 bytes).
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remotes (
  id                      BIGINT       NOT NULL AUTO_INCREMENT,
  url                     TEXT         NOT NULL,
  normalized_url          VARCHAR(768) NOT NULL,
  transport               VARCHAR(16)  NOT NULL
                            CHECK (transport IN ('https','ssh')),
  sync_interval_ns        BIGINT       NOT NULL DEFAULT 300000000000,
  staleness_budget_ns     BIGINT       NOT NULL DEFAULT 0,
  taint_any_tag_deletion  INT          NOT NULL DEFAULT 1,
  hash_algo               VARCHAR(16)  NULL
                            CHECK (hash_algo IS NULL OR hash_algo IN ('sha1','sha256')),
  status                  VARCHAR(16)  NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active','degraded','paused')),
  last_ok_ns              BIGINT       NOT NULL DEFAULT 0,
  last_err                TEXT         NOT NULL,
  consecutive_failures    INT          NOT NULL DEFAULT 0,
  chain_head_hash         VARBINARY(32) NOT NULL,
  chain_len               BIGINT       NOT NULL DEFAULT 0,
  removed_at_ns           BIGINT       NULL,
  created_at_ns           BIGINT       NOT NULL,
  updated_at_ns           BIGINT       NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_remotes_normalized_url (normalized_url),
  KEY idx_remotes_active (status)
) ENGINE=InnoDB;

-- -------------------------------------------------------------------------
-- refs: tags only; per-remote projection, rebuildable from observations.
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refs (
  id                  BIGINT        NOT NULL AUTO_INCREMENT,
  remote_id           BIGINT        NOT NULL,
  tag_name            VARCHAR(512)  NOT NULL,
  current_oid         VARBINARY(32) NULL,
  current_peeled_oid  VARBINARY(32) NULL,
  is_annotated        INT           NOT NULL DEFAULT 0,
  first_oid           VARBINARY(32) NULL,
  first_seen_ns       BIGINT        NOT NULL DEFAULT 0,
  last_seen_ns        BIGINT        NOT NULL DEFAULT 0,
  last_changed_ns     BIGINT        NOT NULL DEFAULT 0,
  deleted             INT           NOT NULL DEFAULT 0,
  tainted             INT           NOT NULL DEFAULT 0,
  taint_first_ns      BIGINT        NULL,
  observation_count   BIGINT        NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE KEY uq_refs_remote_tag (remote_id, tag_name),
  KEY idx_refs_remote (remote_id),
  CONSTRAINT fk_refs_remote FOREIGN KEY (remote_id) REFERENCES remotes(id)
) ENGINE=InnoDB;

-- -------------------------------------------------------------------------
-- syncs: run audit log.
-- Declared before observations because observations.sync_id FK references it.
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS syncs (
  id                BIGINT        NOT NULL AUTO_INCREMENT,
  remote_id         BIGINT        NOT NULL,
  `trigger`         VARCHAR(16)   NOT NULL DEFAULT 'scheduled'
                      CHECK (`trigger` IN ('register','scheduled','manual')),
  started_ns        BIGINT        NOT NULL DEFAULT 0,
  finished_ns       BIGINT        NOT NULL DEFAULT 0,
  status            VARCHAR(16)   NOT NULL DEFAULT 'failed'
                      CHECK (status IN ('ok','partial','failed')),
  tags_seen         INT           NOT NULL DEFAULT 0,
  tags_changed      INT           NOT NULL DEFAULT 0,
  error             TEXT          NOT NULL,
  chain_head_before VARBINARY(32) NULL,
  chain_head_after  VARBINARY(32) NULL,
  PRIMARY KEY (id),
  KEY idx_syncs_remote (remote_id),
  CONSTRAINT fk_syncs_remote FOREIGN KEY (remote_id) REFERENCES remotes(id)
) ENGINE=InnoDB;

-- -------------------------------------------------------------------------
-- observations: APPEND-ONLY per-remote hash-chained ledger. NO UPDATE/DELETE.
-- row_hash = SHA-256(prev_hash || canonical(row))
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS observations (
  id              BIGINT        NOT NULL AUTO_INCREMENT,
  remote_id       BIGINT        NOT NULL,
  ref_id          BIGINT        NOT NULL,
  sync_id         BIGINT        NOT NULL,
  seq             BIGINT        NOT NULL,
  event_type      VARCHAR(32)   NOT NULL
                    CHECK (event_type IN (
                      'tag_created','tag_oid_changed','tag_deleted','tag_recreated'
                    )),
  prev_oid        VARBINARY(32) NULL,
  new_oid         VARBINARY(32) NULL,
  prev_peeled_oid VARBINARY(32) NULL,
  new_peeled_oid  VARBINARY(32) NULL,
  observed_at_ns  BIGINT        NOT NULL,
  prev_hash       VARBINARY(32) NOT NULL,
  row_hash        VARBINARY(32) NOT NULL,
  canonical_meta  TEXT          NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_observations_remote_seq (remote_id, seq),
  KEY idx_observations_ref_ts (ref_id, observed_at_ns),
  CONSTRAINT fk_observations_remote FOREIGN KEY (remote_id) REFERENCES remotes(id),
  CONSTRAINT fk_observations_ref    FOREIGN KEY (ref_id)    REFERENCES refs(id),
  CONSTRAINT fk_observations_sync   FOREIGN KEY (sync_id)   REFERENCES syncs(id)
) ENGINE=InnoDB;

-- -------------------------------------------------------------------------
-- taint_events: IMMUTABLE taint spine.
-- The SQLite UNIQUE (remote_id, ref_id, reason, from_oid, to_oid) includes two
-- NULLable oid columns. In both SQLite and MySQL, NULLs are distinct in a UNIQUE
-- index, so the idempotent ON-CONFLICT/ON-DUPLICATE path only collapses rows
-- whose from_oid/to_oid are both non-NULL (the real taint transitions) — identical
-- semantics across engines.
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS taint_events (
  id               BIGINT        NOT NULL AUTO_INCREMENT,
  remote_id        BIGINT        NOT NULL,
  ref_id           BIGINT        NOT NULL,
  reason           VARCHAR(32)   NOT NULL
                     CHECK (reason IN ('tag_oid_changed','tag_deleted_recreated')),
  observation_id   BIGINT        NULL,
  from_oid         VARBINARY(32) NULL,
  to_oid           VARBINARY(32) NULL,
  detected_at_ns   BIGINT        NOT NULL,
  acked_at_ns      BIGINT        NULL,
  acked_by         TEXT          NULL,
  ack_note         TEXT          NULL,
  detail           TEXT          NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_taint_dedup (remote_id, ref_id, reason, from_oid, to_oid),
  KEY idx_taint_remote (remote_id),
  CONSTRAINT fk_taint_remote      FOREIGN KEY (remote_id)      REFERENCES remotes(id),
  CONSTRAINT fk_taint_ref         FOREIGN KEY (ref_id)         REFERENCES refs(id),
  CONSTRAINT fk_taint_observation FOREIGN KEY (observation_id) REFERENCES observations(id)
) ENGINE=InnoDB;

-- -------------------------------------------------------------------------
-- remote_lease: Lock seam — DB-backed per-remote writer lease.
-- PK is remote_id (one active lease per remote at a time).
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remote_lease (
  remote_id      BIGINT      NOT NULL,
  holder         VARCHAR(255) NOT NULL,
  acquired_at_ns BIGINT      NOT NULL,
  expires_at_ns  BIGINT      NOT NULL,
  PRIMARY KEY (remote_id),
  CONSTRAINT fk_lease_remote FOREIGN KEY (remote_id) REFERENCES remotes(id)
) ENGINE=InnoDB;
