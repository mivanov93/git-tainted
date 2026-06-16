package config

import (
	"errors"
	"testing"
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
				if c.SyncDefaultIntervalNS != 300_000_000_000 {
					t.Errorf("SyncDefaultIntervalNS = %d, want 300e9", c.SyncDefaultIntervalNS)
				}
				if c.SchedulerTickNS != 5_000_000_000 {
					t.Errorf("SchedulerTickNS = %d, want 5e9", c.SchedulerTickNS)
				}
				if c.StalenessBudgetNS != 3_600_000_000_000 {
					t.Errorf("StalenessBudgetNS = %d, want 3600e9", c.StalenessBudgetNS)
				}
				if c.GitBin != "git" {
					t.Errorf("GitBin = %q, want git", c.GitBin)
				}
				if c.GitTimeoutNS != 60_000_000_000 {
					t.Errorf("GitTimeoutNS = %d, want 60e9", c.GitTimeoutNS)
				}
				if c.ProtocolAllowlist != "https:ssh" {
					t.Errorf("ProtocolAllowlist = %q, want https:ssh", c.ProtocolAllowlist)
				}
				if c.LogLevel != "info" {
					t.Errorf("LogLevel = %q, want info", c.LogLevel)
				}
				if c.MetricsAddr != "127.0.0.1:9090" {
					t.Errorf("MetricsAddr = %q, want loopback default", c.MetricsAddr)
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
			},
			want: func(t *testing.T, c *Config) {
				if c.SyncConcurrency != 8 {
					t.Errorf("SyncConcurrency = %d, want 8", c.SyncConcurrency)
				}
				if c.HostAllowlist != "github.com,gitlab.com" {
					t.Errorf("HostAllowlist = %q", c.HostAllowlist)
				}
				if c.StalenessBudgetNS != 7200000000000 {
					t.Errorf("StalenessBudgetNS = %d, want 7200e9", c.StalenessBudgetNS)
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
