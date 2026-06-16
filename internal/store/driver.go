// Package store implements model.Store over sqlc-generated queries against
// modernc.org/sqlite (pure-Go, CGO-free). hex↔raw oid conversion is centralized
// at this boundary; chain/ancestry/generation logic lives in sibling files. The
// real schema (db/migrations/0001_init.sql) and queries land in Phase 1.
package store

import (
	// Registers the pure-Go sqlite driver (CGO-free) under the name "sqlite".
	_ "modernc.org/sqlite"

	// Registers the pure-Go MySQL driver (CGO-free) under the name "mysql" for
	// the second model.Store implementation (mysqlStore). The two-impls-per-seam
	// pattern: identical model.Store contract, SQLite default, MySQL optional.
	_ "github.com/go-sql-driver/mysql"
)

// DriverName is the database/sql driver name registered by the blank sqlite
// import above (modernc.org/sqlite, pure-Go static, no CGO).
const DriverName = "sqlite"

// MySQLDriverName is the database/sql driver name registered by the blank
// go-sql-driver/mysql import above (pure-Go, CGO-free).
const MySQLDriverName = "mysql"
