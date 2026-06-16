package store

import (
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

// migrateNowNS returns the current wall time as unix-nanoseconds. The migration
// runners execute before the Store is open and before the Clock seam is
// injected, so they use wall time directly (not the model.Clock seam).
func migrateNowNS() int64 { return time.Now().UnixNano() }

// RunMigrations applies all *.sql files in fsys (in lexical/numeric order),
// tracking applied versions in schema_migrations. Each file runs in its own
// transaction. Idempotent: already-applied versions are skipped without error.
// The schema_migrations table is created if absent (bootstrapping the first
// run). fsys is rooted at the .sql files (e.g. db.SQLiteMigrations).
func RunMigrations(db *sql.DB, fsys fs.FS) error {
	// Bootstrap: create schema_migrations if it does not exist yet.
	// This must happen outside any per-migration txn so it is visible on the
	// first pass even before 0001_init.sql creates it.
	const bootstrapDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
		version       INTEGER PRIMARY KEY,
		applied_at_ns BIGINT NOT NULL
	)`
	if _, err := db.Exec(bootstrapDDL); err != nil {
		return fmt.Errorf("migrate: bootstrap schema_migrations: %w", err)
	}

	migs, err := collectMigrations(fsys)
	if err != nil {
		return err
	}

	for _, m := range migs {
		// Check if already applied.
		var exists int
		err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version).Scan(&exists)
		if err != nil {
			return fmt.Errorf("migrate: check version %d: %w", m.version, err)
		}
		if exists > 0 {
			continue // already applied; skip
		}

		ddl, err := fs.ReadFile(fsys, m.name)
		if err != nil {
			return fmt.Errorf("migrate: read %s: %w", m.name, err)
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("migrate: begin txn for version %d: %w", m.version, err)
		}
		if _, err := tx.Exec(string(ddl)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrate: apply version %d (%s): %w", m.version, m.name, err)
		}
		// Record as applied using a wall-clock ns timestamp.
		if _, err := tx.Exec(
			`INSERT INTO schema_migrations (version, applied_at_ns) VALUES (?, ?)`,
			m.version, migrateNowNS(),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrate: record version %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrate: commit version %d: %w", m.version, err)
		}
	}
	return nil
}

// RunMigrationsMySQL is the MySQL variant of RunMigrations. MySQL DDL statements
// implicitly COMMIT, so wrapping a migration file in a transaction gives no
// atomicity (a multi-statement file that fails midway leaves the earlier tables
// committed). Correctness therefore rests on every CREATE TABLE using
// IF NOT EXISTS (so a re-run after a partial failure is a no-op), not on
// transactional rollback. The migration file itself must be executed as a
// multi-statement script, which requires the DSN to carry multiStatements=true.
//
// The schema_migrations bookkeeping marker is written only AFTER the file's DDL
// succeeds; if the process dies mid-file, the version is not recorded and the
// next run re-applies the whole (idempotent) file. fsys is rooted at the .sql
// files (e.g. db.MySQLMigrations).
func RunMigrationsMySQL(db *sql.DB, fsys fs.FS) error {
	const bootstrapDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
		version       INT    NOT NULL,
		applied_at_ns BIGINT NOT NULL,
		PRIMARY KEY (version)
	) ENGINE=InnoDB`
	if _, err := db.Exec(bootstrapDDL); err != nil {
		return fmt.Errorf("migrate(mysql): bootstrap schema_migrations: %w", err)
	}

	migs, err := collectMigrations(fsys)
	if err != nil {
		return err
	}

	for _, m := range migs {
		var exists int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version,
		).Scan(&exists); err != nil {
			return fmt.Errorf("migrate(mysql): check version %d: %w", m.version, err)
		}
		if exists > 0 {
			continue
		}

		ddl, err := fs.ReadFile(fsys, m.name)
		if err != nil {
			return fmt.Errorf("migrate(mysql): read %s: %w", m.name, err)
		}
		// No txn wrapper: MySQL DDL auto-commits. IF NOT EXISTS makes re-runs safe.
		if _, err := db.Exec(string(ddl)); err != nil {
			return fmt.Errorf("migrate(mysql): apply version %d (%s): %w", m.version, m.name, err)
		}
		if _, err := db.Exec(
			`INSERT INTO schema_migrations (version, applied_at_ns) VALUES (?, ?)`,
			m.version, migrateNowNS(),
		); err != nil {
			return fmt.Errorf("migrate(mysql): record version %d: %w", m.version, err)
		}
	}
	return nil
}

// migration is one discovered, version-prefixed .sql file (name is relative to
// the migrations fs.FS root).
type migration struct {
	version int64
	name    string
}

// collectMigrations lists and sorts the version-prefixed .sql files at the root
// of fsys. Shared by the SQLite and MySQL runners.
func collectMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("migrate: read migrations fs: %w", err)
	}
	var migs []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		prefix := strings.SplitN(e.Name(), "_", 2)[0]
		ver, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("migrate: cannot parse version from %q: %w", e.Name(), err)
		}
		migs = append(migs, migration{version: ver, name: e.Name()})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })
	return migs, nil
}
