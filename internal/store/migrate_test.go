package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRoot walks up from the test binary's source file to find go.mod.
func repoRoot(tb testing.TB) string {
	tb.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			tb.Fatal("go.mod not found walking to repo root")
		}
		dir = parent
	}
}

func TestSchemaInit(t *testing.T) {
	root := repoRoot(t)
	ddl, err := os.ReadFile(filepath.Join(root, "db", "migrations", "0001_init.sql")) //nolint:gosec // G304: test fixture path built from repoRoot
	if err != nil {
		t.Fatalf("read 0001_init.sql: %v", err)
	}

	db, err := sql.Open(DriverName, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(string(ddl)); err != nil {
		t.Fatalf("exec DDL: %v", err)
	}

	// §9 schema: these tables must exist; old tables (projects/project_ref_state/
	// commit_node/commit_edge/signatures/ref_signatures) must NOT exist.
	want := []string{
		"schema_migrations",
		"remotes",
		"refs",
		"observations",
		"taint_events",
		"syncs",
		"remote_lease",
	}
	mustNotExist := []string{
		"projects",
		"project_ref_state",
		"commit_node",
		"commit_edge",
		"signatures",
		"ref_signatures",
	}

	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		got[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	for _, tbl := range want {
		if !got[tbl] {
			t.Errorf("table %q missing from schema", tbl)
		}
	}
	for _, tbl := range mustNotExist {
		if got[tbl] {
			t.Errorf("removed table %q must not exist in schema", tbl)
		}
	}
}

func TestSchemaMigrationsTable(t *testing.T) {
	root := repoRoot(t)
	ddl, err := os.ReadFile(filepath.Join(root, "db", "migrations", "0001_init.sql")) //nolint:gosec // G304: test fixture path built from repoRoot
	if err != nil {
		t.Fatalf("read 0001_init.sql: %v", err)
	}
	db, err := sql.Open(DriverName, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(string(ddl)); err != nil {
		t.Fatalf("exec DDL: %v", err)
	}
	// schema_migrations must have (version INTEGER PK, applied_at_ns BIGINT).
	var cnt int
	err = db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('schema_migrations') WHERE name IN ('version','applied_at_ns')`,
	).Scan(&cnt)
	if err != nil {
		t.Fatalf("pragma query: %v", err)
	}
	if cnt != 2 {
		t.Errorf("schema_migrations must have version + applied_at_ns columns, found %d", cnt)
	}
}

func TestMigrateRunner_FreshAndIdempotent(t *testing.T) {
	root := repoRoot(t)
	migrDir := filepath.Join(root, "db", "migrations")

	db, err := sql.Open(DriverName, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// First run: fresh migration.
	if err := runMigrations(db, migrDir); err != nil {
		t.Fatalf("first migrate: %v", err)
	}

	// Confirm version 1 recorded.
	var ver int64
	if err := db.QueryRow(`SELECT version FROM schema_migrations WHERE version = 1`).Scan(&ver); err != nil {
		t.Fatalf("version 1 not recorded: %v", err)
	}
	if ver != 1 {
		t.Errorf("version = %d, want 1", ver)
	}

	// Count the actual migration files so the assertion stays correct as files are added.
	entries, err := os.ReadDir(migrDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var wantRows int
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".sql" {
			wantRows++
		}
	}

	// Second run: must be a no-op (idempotent), no error.
	if err := runMigrations(db, migrDir); err != nil {
		t.Fatalf("second migrate (idempotent): %v", err)
	}

	// Row count must equal the number of .sql migration files (each applied exactly once).
	var cnt int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&cnt); err != nil {
		t.Fatalf("count: %v", err)
	}
	if cnt != wantRows {
		t.Errorf("schema_migrations rows = %d, want %d after idempotent re-run", cnt, wantRows)
	}
}

func TestMigrateRunner_MissingDirFails(t *testing.T) {
	db, err := sql.Open(DriverName, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := runMigrations(db, "/nonexistent/path/migrations"); err == nil {
		t.Errorf("missing migrations dir must return error")
	}
}

func TestSchemaCheckConstraints(t *testing.T) {
	root := repoRoot(t)
	ddl, err := os.ReadFile(filepath.Join(root, "db", "migrations", "0001_init.sql")) //nolint:gosec // G304: test fixture path built from repoRoot
	if err != nil {
		t.Fatalf("read 0001_init.sql: %v", err)
	}
	db, err := sql.Open(DriverName, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	// Enable foreign keys + strict CHECK enforcement.
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(ddl)); err != nil {
		t.Fatalf("exec DDL: %v", err)
	}

	genesis := make([]byte, 32) // 32 zero bytes

	// A remotes row with an invalid transport must be rejected.
	_, err = db.Exec(`INSERT INTO remotes
		(url, normalized_url, transport,
		 sync_interval_ns, staleness_budget_ns, taint_any_tag_deletion,
		 status, last_err, consecutive_failures,
		 chain_head_hash, chain_len, created_at_ns, updated_at_ns)
		VALUES ('https://x.com/r', 'https://x.com/r', 'ftp',
		        300000000000, 3600000000000, 1,
		        'active', '', 0,
		        ?, 0, 1718000000000000000, 1718000000000000000)`,
		genesis)
	if err == nil {
		t.Errorf("expected CHECK constraint violation for bad transport, got nil")
	} else if !strings.Contains(err.Error(), "CHECK") && !strings.Contains(err.Error(), "constraint") {
		t.Errorf("expected CHECK constraint error, got: %v", err)
	}

	// Insert a valid remote to test refs CHECK below.
	_, err = db.Exec(`INSERT INTO remotes
		(url, normalized_url, transport,
		 sync_interval_ns, staleness_budget_ns, taint_any_tag_deletion,
		 status, last_err, consecutive_failures,
		 chain_head_hash, chain_len, created_at_ns, updated_at_ns)
		VALUES ('https://x.com/r', 'https://x.com/r', 'https',
		        300000000000, 3600000000000, 1,
		        'active', '', 0,
		        ?, 0, 1718000000000000000, 1718000000000000000)`,
		genesis)
	if err != nil {
		t.Fatalf("valid remote insert: %v", err)
	}
}
