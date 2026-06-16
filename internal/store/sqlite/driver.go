// Package sqlite implements model.Store over sqlc-generated queries against
// modernc.org/sqlite (pure-Go, CGO-free). hex↔raw oid conversion is centralized
// at this boundary; the dialect-agnostic chain/migration logic lives in the
// parent internal/store package (store.CanonicalRow, store.RowHash,
// store.RunMigrations). The real schema lives in db/migrations-sqlite and is
// embedded into the binary via the db package.
package sqlite

import (
	// Registers the pure-Go sqlite driver (CGO-free) under the name "sqlite".
	_ "modernc.org/sqlite"
)

// DriverName is the database/sql driver name registered by the blank sqlite
// import above (modernc.org/sqlite, pure-Go static, no CGO).
const DriverName = "sqlite"
