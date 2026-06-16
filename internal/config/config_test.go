package config

import (
	"errors"
	"testing"
	"time"
)

func lookup(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    func(*testing.T, *Config)
		wantErr error
	}{
		{
			name: "defaults applied when keys absent",
			env: map[string]string{
				"GT_SQLITE_PATH": "/data/git-tainted.db",
			},
			want: func(t *testing.T, c *Config) {
				if c.DBDriver != "sqlite" {
					t.Errorf("DBDriver = %q, want sqlite", c.DBDriver)
				}
				if c.ListenAddr != "127.0.0.1:8080" {
					t.Errorf("ListenAddr = %q, want loopback default", c.ListenAddr)
				}
				if c.SyncConcurrency != 4 {
					t.Errorf("SyncConcurrency = %d, want 4", c.SyncConcurrency)
				}
				if c.SyncDefaultInterval != 5*time.Minute {
					t.Errorf("SyncDefaultInterval = %d, want 5m", c.SyncDefaultInterval)
				}
				if c.SchedulerTick != 5*time.Second {
					t.Errorf("SchedulerTick = %d, want 5s", c.SchedulerTick)
				}
				if c.StalenessBudget != time.Hour {
					t.Errorf("StalenessBudget = %d, want 1h", c.StalenessBudget)
				}
				if c.GitBin != "git" {
					t.Errorf("GitBin = %q, want git", c.GitBin)
				}
				if c.GitTimeout != time.Minute {
					t.Errorf("GitTimeout = %d, want 60s", c.GitTimeout)
				}
				if c.ProtocolAllowlist != "https:ssh" {
					t.Errorf("ProtocolAllowlist = %q, want https:ssh", c.ProtocolAllowlist)
				}
				if c.LogLevel != "info" {
					t.Errorf("LogLevel = %q, want info", c.LogLevel)
				}
				// Default MetricsAddr is empty (metrics disabled by default).
				if c.MetricsAddr != "" {
					t.Errorf("MetricsAddr = %q, want empty (disabled by default)", c.MetricsAddr)
				}
				if c.PprofEnabled {
					t.Errorf("PprofEnabled = true, want false (disabled by default)")
				}
				// Verify hot-path cache is ON by default with the §4.6 defaults.
				if !c.CacheEnabled {
					t.Errorf("CacheEnabled = false, want true (cache on by default)")
				}
				if c.CacheMaxEntries != 100_000 {
					t.Errorf("CacheMaxEntries = %d, want 100000", c.CacheMaxEntries)
				}
				if c.CacheTTL != time.Minute {
					t.Errorf("CacheTTL = %d, want 60s", c.CacheTTL)
				}
			},
		},
		{
			name: "all keys overridden",
			env: map[string]string{
				"GT_DB_DRIVER":                "sqlite",
				"GT_SQLITE_PATH":              "/var/db.sqlite",
				"GT_LISTEN_ADDR":              "0.0.0.0:8080",
				"GT_SYNC_CONCURRENCY":         "8",
				"GT_SYNC_DEFAULT_INTERVAL_NS": "120000000000",
				"GT_SCHEDULER_TICK_NS":        "2000000000",
				"GT_STALENESS_BUDGET_NS":      "7200000000000",
				"GT_GIT_BIN":                  "/usr/bin/git",
				"GT_GIT_TIMEOUT_NS":           "30000000000",
				"GT_PROTOCOL_ALLOWLIST":       "https",
				"GT_HOST_ALLOWLIST":           "github.com,gitlab.com",
				"GT_LOG_LEVEL":                "debug",
				"GT_METRICS_ADDR":             "0.0.0.0:9090",
				"GT_CACHE_ENABLED":            "false",
				"GT_CACHE_MAX_ENTRIES":        "5000",
				"GT_CACHE_TTL_NS":             "0",
			},
			want: func(t *testing.T, c *Config) {
				if c.SyncConcurrency != 8 {
					t.Errorf("SyncConcurrency = %d, want 8", c.SyncConcurrency)
				}
				if c.HostAllowlist != "github.com,gitlab.com" {
					t.Errorf("HostAllowlist = %q", c.HostAllowlist)
				}
				if c.StalenessBudget != 2*time.Hour {
					t.Errorf("StalenessBudget = %d, want 2h", c.StalenessBudget)
				}
				if c.CacheEnabled {
					t.Errorf("CacheEnabled = true, want false (GT_CACHE_ENABLED=false)")
				}
				if c.CacheMaxEntries != 5000 {
					t.Errorf("CacheMaxEntries = %d, want 5000", c.CacheMaxEntries)
				}
				// TTL=0 is a valid override (disables the TTL backstop).
				if c.CacheTTL != 0 {
					t.Errorf("CacheTTL = %d, want 0", c.CacheTTL)
				}
			},
		},
		{
			name:    "missing sqlite path fails",
			env:     map[string]string{},
			wantErr: ErrConfig,
		},
		{
			name: "non-numeric interval fails",
			env: map[string]string{
				"GT_SQLITE_PATH":              "/data/x.db",
				"GT_SYNC_DEFAULT_INTERVAL_NS": "not-a-number",
			},
			wantErr: ErrConfig,
		},
		{
			name: "non-positive concurrency fails",
			env: map[string]string{
				"GT_SQLITE_PATH":      "/data/x.db",
				"GT_SYNC_CONCURRENCY": "0",
			},
			wantErr: ErrConfig,
		},
		{
			name: "mysql driver without DSN fails",
			env: map[string]string{
				"GT_DB_DRIVER": "mysql",
			},
			wantErr: ErrConfig,
		},
		{
			name: "mysql driver with DSN ok (no sqlite path required)",
			env: map[string]string{
				"GT_DB_DRIVER": "mysql",
				"GT_MYSQL_DSN": "user:pass@tcp(127.0.0.1:3306)/git_tainted?multiStatements=true",
			},
			want: func(t *testing.T, c *Config) {
				t.Helper()
				if c.DBDriver != "mysql" {
					t.Errorf("DBDriver = %q, want mysql", c.DBDriver)
				}
				if c.MySQLDSN == "" {
					t.Errorf("MySQLDSN must be set")
				}
			},
		},
		{
			name: "unknown driver fails",
			env: map[string]string{
				"GT_DB_DRIVER":   "postgres",
				"GT_SQLITE_PATH": "/data/x.db",
			},
			wantErr: ErrConfig,
		},
		{
			name: "GT_METRICS_ADDR and GT_PPROF_ENABLED parsed",
			env: map[string]string{
				"GT_SQLITE_PATH":   "/data/x.db",
				"GT_METRICS_ADDR":  "127.0.0.1:9090",
				"GT_PPROF_ENABLED": "true",
			},
			want: func(t *testing.T, c *Config) {
				t.Helper()
				if c.MetricsAddr != "127.0.0.1:9090" {
					t.Errorf("MetricsAddr = %q, want 127.0.0.1:9090", c.MetricsAddr)
				}
				if !c.PprofEnabled {
					t.Errorf("PprofEnabled = false, want true")
				}
			},
		},
		{
			name: "GT_PPROF_ENABLED=1 is true",
			env: map[string]string{
				"GT_SQLITE_PATH":   "/data/x.db",
				"GT_PPROF_ENABLED": "1",
			},
			want: func(t *testing.T, c *Config) {
				t.Helper()
				if !c.PprofEnabled {
					t.Errorf("PprofEnabled = false, want true for value '1'")
				}
			},
		},
		{
			name: "GT_PPROF_ENABLED=false stays false",
			env: map[string]string{
				"GT_SQLITE_PATH":   "/data/x.db",
				"GT_PPROF_ENABLED": "false",
			},
			want: func(t *testing.T, c *Config) {
				t.Helper()
				if c.PprofEnabled {
					t.Errorf("PprofEnabled = true, want false for value 'false'")
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(lookup(tc.env))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Load err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load unexpected err: %v", err)
			}
			if tc.want != nil {
				tc.want(t, cfg)
			}
		})
	}
}
