// Package store implements model.Store over sqlc-generated queries against
// modernc.org/sqlite (pure-Go, CGO-free). hex↔raw oid conversion is centralized
// at this boundary; chain/ancestry/generation logic lives in sibling files. The
// real schema (db/migrations/0001_init.sql) and queries land in Phase 1.
package store

import (
	// Registers the pure-Go sqlite driver (CGO-free) under the name "sqlite".
	_ "modernc.org/sqlite"
)

// DriverName is the database/sql driver name registered by the blank import
// above (modernc.org/sqlite, pure-Go static, no CGO).
const DriverName = "sqlite"
