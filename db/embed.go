// Package db embeds the SQL migration sets into the binary so the server runs
// with no db/ folder on disk. Each engine's migrations are exposed as an fs.FS
// rooted at its .sql files (so a runner sees "0001_init.sql", not
// "migrations-sqlite/0001_init.sql"). The store migration runners
// (store.RunMigrations / store.RunMigrationsMySQL) read from these fs.FS values.
package db

import (
	"embed"
	"io/fs"
)

//go:embed migrations-sqlite
var sqliteFS embed.FS

//go:embed migrations-mysql
var mysqlFS embed.FS

// SQLiteMigrations is the SQLite migration set, rooted at the .sql files.
var SQLiteMigrations, _ = fs.Sub(sqliteFS, "migrations-sqlite")

// MySQLMigrations is the MySQL migration set, rooted at the .sql files.
var MySQLMigrations, _ = fs.Sub(mysqlFS, "migrations-mysql")
