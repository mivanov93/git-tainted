package store

import (
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	// Test-only: register the pure-Go sqlite driver so the dialect-agnostic
	// migration runner can be exercised against an in-memory DB. The parent
	// store package itself imports only internal/model + stdlib; the backend
	// subpackages own the production driver imports.
	_ "modernc.org/sqlite"
)

// sqliteTestDriver is the database/sql driver name used by these runner tests.
const sqliteTestDriver = "sqlite"

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

// sqliteMigrationsFS returns an fs.FS rooted at the on-disk SQLite migration
// set (db/migrations-sqlite), exercising the real DDL through the fs.FS runner.
func sqliteMigrationsFS(tb testing.TB) fs.FS {
	tb.Helper()
	return os.DirFS(filepath.Join(repoRoot(tb), "db", "migrations-sqlite"))
}

func TestSchemaInit(t *testing.T) {
	ddl, err := fs.ReadFile(sqliteMigrationsFS(t), "0001_init.sql")
	if err != nil {
		t.Fatalf("read 0001_init.sql: %v", err)
	}

	db, err := sql.Open(sqliteTestDriver, ":memory:")
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
	ddl, err := fs.ReadFile(sqliteMigrationsFS(t), "0001_init.sql")
	if err != nil {
		t.Fatalf("read 0001_init.sql: %v", err)
	}
	db, err := sql.Open(sqliteTestDriver, ":memory:")
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
	migrFS := sqliteMigrationsFS(t)

	db, err := sql.Open(sqliteTestDriver, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// First run: fresh migration.
	if err := RunMigrations(db, migrFS); err != nil {
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
	entries, err := fs.ReadDir(migrFS, ".")
	if err != nil {
		t.Fatalf("read migrations fs: %v", err)
	}
	var wantRows int
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			wantRows++
		}
	}

	// Second run: must be a no-op (idempotent), no error.
	if err := RunMigrations(db, migrFS); err != nil {
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

// TestMigrateRunner_MapFSOrdering proves the runner applies files in numeric
// order from an arbitrary fs.FS (not just the on-disk set) and that the version
// prefix is parsed from the filename.
func TestMigrateRunner_MapFSOrdering(t *testing.T) {
	migrFS := fstest.MapFS{
		"0002_second.sql": {Data: []byte(`CREATE TABLE t2 (id INTEGER PRIMARY KEY)`)},
		"0001_first.sql":  {Data: []byte(`CREATE TABLE t1 (id INTEGER PRIMARY KEY)`)},
		"README.md":       {Data: []byte("not a migration")}, // must be ignored
	}
	db, err := sql.Open(sqliteTestDriver, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := RunMigrations(db, migrFS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Both versions recorded, exactly two rows (README ignored).
	var cnt int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&cnt); err != nil {
		t.Fatalf("count: %v", err)
	}
	if cnt != 2 {
		t.Errorf("schema_migrations rows = %d, want 2", cnt)
	}
	for _, v := range []int64{1, 2} {
		var got int64
		if err := db.QueryRow(`SELECT version FROM schema_migrations WHERE version = ?`, v).Scan(&got); err != nil {
			t.Errorf("version %d not recorded: %v", v, err)
		}
	}
}

// TestMigrateRunner_BadVersionPrefixFails proves a non-numeric version prefix is
// rejected (replaces the old missing-dir test, which is moot now that the
// migrations are an in-binary fs.FS).
func TestMigrateRunner_BadVersionPrefixFails(t *testing.T) {
	migrFS := fstest.MapFS{
		"bogus_name.sql": {Data: []byte(`CREATE TABLE x (id INTEGER PRIMARY KEY)`)},
	}
	db, err := sql.Open(sqliteTestDriver, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := RunMigrations(db, migrFS); err == nil {
		t.Errorf("migration with non-numeric version prefix must return error")
	}
}

func TestSchemaCheckConstraints(t *testing.T) {
	ddl, err := fs.ReadFile(sqliteMigrationsFS(t), "0001_init.sql")
	if err != nil {
		t.Fatalf("read 0001_init.sql: %v", err)
	}
	db, err := sql.Open(sqliteTestDriver, ":memory:")
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
