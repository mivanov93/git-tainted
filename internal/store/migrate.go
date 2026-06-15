package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// runMigrations applies all *.sql files in migrDir in lexical order, tracking
// applied versions in schema_migrations. Each file runs in its own transaction.
// Idempotent: already-applied versions are skipped without error. The
// schema_migrations table is created if absent (bootstrapping the first run).
func runMigrations(db *sql.DB, migrDir string) error {
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

	entries, err := os.ReadDir(migrDir)
	if err != nil {
		return fmt.Errorf("migrate: read dir %s: %w", migrDir, err)
	}

	// Collect and sort .sql files by their 4-digit numeric prefix.
	type mig struct {
		version int64
		path    string
	}
	var migs []mig
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		prefix := strings.SplitN(e.Name(), "_", 2)[0]
		ver, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			return fmt.Errorf("migrate: cannot parse version from %q: %w", e.Name(), err)
		}
		migs = append(migs, mig{version: ver, path: filepath.Join(migrDir, e.Name())})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })

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

		ddl, err := os.ReadFile(m.path)
		if err != nil {
			return fmt.Errorf("migrate: read %s: %w", m.path, err)
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("migrate: begin txn for version %d: %w", m.version, err)
		}
		if _, err := tx.Exec(string(ddl)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrate: apply version %d (%s): %w", m.version, filepath.Base(m.path), err)
		}
		// Record as applied using a wall-clock ns timestamp.
		// The migration runner does not use the Clock seam — it runs before the
		// Store is open and before the Clock is injected.
		if _, err := tx.Exec(
			`INSERT INTO schema_migrations (version, applied_at_ns) VALUES (?, ?)`,
			m.version, nowNS(),
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
