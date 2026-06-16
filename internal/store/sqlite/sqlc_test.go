package sqlite

import (
	"database/sql"
	"testing"

	"github.com/mivanov93/git-tainted/internal/store/sqlite/sqlc"
)

func TestSQLCGeneratedPackageCompiles(t *testing.T) {
	// If the sqlc package does not exist or does not compile, this test file
	// itself will fail to compile, giving an unambiguous signal.
	db, err := sql.Open(DriverName, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Construct a Queries value to prove the generated type exists.
	q := sqlc.New(db)
	if q == nil {
		t.Fatal("sqlc.New returned nil")
	}
}
