// Package config loads the GT_* environment (design spec §11) into a validated
// Config. Durations are int64 unix-ns ints (no time.Duration in the config
// surface, per the unix-ns-everywhere convention). Load is pure over a lookup
// function so it is deterministic in tests; LoadEnv binds it to the process env.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

// ErrConfig is the sentinel for any configuration validation/parse failure.
var ErrConfig = errors.New("config: invalid configuration")

// Config is the fully-resolved service configuration (design spec §11).
type Config struct {
	DBDriver              string
	SQLitePath            string
	ListenAddr            string
	SyncConcurrency       int
	SyncDefaultIntervalNS int64
	SchedulerTickNS       int64
	StalenessBudgetNS     int64
	GitBin                string
	GitTimeoutNS          int64
	ProtocolAllowlist     string
	HostAllowlist         string
	LogLevel              string
	MetricsAddr           string
}

// Lookup resolves an env key to its value and presence, mirroring os.LookupEnv.
type Lookup func(key string) (string, bool)

// LoadEnv loads Config from the process environment.
func LoadEnv() (*Config, error) { return Load(os.LookupEnv) }

// Load builds and validates a Config from get. It applies §11 defaults for
// absent keys, parses every *_NS / *_CONCURRENCY key as an integer,
// and returns ErrConfig (wrapped) on any missing-required, parse, or
// range/enum violation.
func Load(get Lookup) (*Config, error) {
	str := func(key, def string) string {
		if v, ok := get(key); ok {
			return v
		}
		return def
	}
	i64 := func(key string, def int64) (int64, error) {
		v, ok := get(key)
		if !ok {
			return def, nil
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: %s=%q is not an integer: %w", ErrConfig, key, v, err)
		}
		return n, nil
	}
	iInt := func(key string, def int) (int, error) {
		n, err := i64(key, int64(def))
		if err != nil {
			return 0, err
		}
		return int(n), nil
	}

	c := &Config{
		DBDriver:          str("GT_DB_DRIVER", "sqlite"),
		SQLitePath:        str("GT_SQLITE_PATH", ""),
		ListenAddr:        str("GT_LISTEN_ADDR", "127.0.0.1:8080"),
		GitBin:            str("GT_GIT_BIN", "git"),
		ProtocolAllowlist: str("GT_PROTOCOL_ALLOWLIST", "https:ssh"),
		HostAllowlist:     str("GT_HOST_ALLOWLIST", ""),
		LogLevel:          str("GT_LOG_LEVEL", "info"),
		MetricsAddr:       str("GT_METRICS_ADDR", "127.0.0.1:9090"),
	}

	var err error
	if c.SyncConcurrency, err = iInt("GT_SYNC_CONCURRENCY", 4); err != nil {
		return nil, err
	}
	if c.SyncDefaultIntervalNS, err = i64("GT_SYNC_DEFAULT_INTERVAL_NS", 300_000_000_000); err != nil {
		return nil, err
	}
	if c.SchedulerTickNS, err = i64("GT_SCHEDULER_TICK_NS", 5_000_000_000); err != nil {
		return nil, err
	}
	if c.StalenessBudgetNS, err = i64("GT_STALENESS_BUDGET_NS", 3_600_000_000_000); err != nil {
		return nil, err
	}
	if c.GitTimeoutNS, err = i64("GT_GIT_TIMEOUT_NS", 60_000_000_000); err != nil {
		return nil, err
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	if c.DBDriver != "sqlite" {
		return fmt.Errorf("%w: GT_DB_DRIVER=%q unsupported (only sqlite in v1)", ErrConfig, c.DBDriver)
	}
	if c.SQLitePath == "" {
		return fmt.Errorf("%w: GT_SQLITE_PATH is required for the sqlite driver", ErrConfig)
	}
	if c.SyncConcurrency <= 0 {
		return fmt.Errorf("%w: GT_SYNC_CONCURRENCY=%d must be > 0", ErrConfig, c.SyncConcurrency)
	}
	if c.SyncDefaultIntervalNS <= 0 {
		return fmt.Errorf("%w: GT_SYNC_DEFAULT_INTERVAL_NS=%d must be > 0", ErrConfig, c.SyncDefaultIntervalNS)
	}
	if c.SchedulerTickNS <= 0 {
		return fmt.Errorf("%w: GT_SCHEDULER_TICK_NS=%d must be > 0", ErrConfig, c.SchedulerTickNS)
	}
	if c.GitTimeoutNS <= 0 {
		return fmt.Errorf("%w: GT_GIT_TIMEOUT_NS=%d must be > 0", ErrConfig, c.GitTimeoutNS)
	}
	if c.StalenessBudgetNS <= 0 {
		return fmt.Errorf("%w: GT_STALENESS_BUDGET_NS=%d must be > 0", ErrConfig, c.StalenessBudgetNS)
	}
	return nil
}
