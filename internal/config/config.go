// Package config loads the GT_* environment (design spec §11) into a validated
// Config. The GT_*_NS env vars carry int64 unix-ns on the wire, but genuine
// durations are surfaced as time.Duration on Config (the dur loader parses the
// ns int then wraps it); only timestamps stay int64-ns. Load is pure over a
// lookup function so it is deterministic in tests; LoadEnv binds it to the
// process env.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrConfig is the sentinel for any configuration validation/parse failure.
var ErrConfig = errors.New("config: invalid configuration")

// Auth modes for GT_AUTH_MODE (control-plane design spec §2). Default is None,
// which reproduces the pre-auth loopback/edge-proxy posture exactly.
const (
	AuthModeNone   = "none"
	AuthModeAPIKey = "apikey"
	AuthModeBasic  = "basic"
	AuthModeJWKS   = "jwks"
)

// Config is the fully-resolved service configuration (design spec §11).
type Config struct {
	DBDriver            string
	SQLitePath          string
	MySQLDSN            string
	ListenAddr          string
	SyncConcurrency     int
	SyncDefaultInterval time.Duration
	SchedulerTick       time.Duration
	StalenessBudget     time.Duration
	GitBin              string
	GitTimeout          time.Duration
	ProtocolAllowlist   string
	HostAllowlist       string
	LogLevel            string
	// MetricsAddr is the dedicated Prometheus listener address.
	// Empty (default) means metrics are DISABLED — no collection, no /metrics endpoint.
	MetricsAddr  string
	PprofEnabled bool

	// ---- Verify hot-path cache (control-plane design spec §4) --------------
	// CacheEnabled turns on the Otter caching Store decorator (default true).
	// When false, cache.Wrap returns the inner store unchanged (zero overhead).
	CacheEnabled bool
	// CacheMaxEntries bounds each logical Otter cache (size-based eviction).
	CacheMaxEntries int
	// CacheTTL is the staleness backstop, independent of the (immediate)
	// per-remote generation invalidation. 0 disables TTL expiry.
	CacheTTL time.Duration

	// ---- Control-plane auth (design spec §2) -------------------------------
	// AuthMode selects how the five mutating control endpoints are gated:
	// none (default) | apikey | basic | jwks. Reads/health are never gated.
	AuthMode string
	// apikey mode.
	APIKeys       string // comma-separated raw keys (SHA-256-hashed at load)
	APIKeysSHA256 string // comma-separated lowercase-hex SHA-256 digests
	// basic mode.
	BasicAuth string // comma-separated user:bcrypt-hash entries
	// jwks mode.
	JWKSURL     string // JWKS endpoint URL (required for jwks)
	JWTIssuer   string // expected iss (required for jwks)
	JWTAudience string // expected aud (required for jwks)
	JWTAlgs     string // comma-separated signature-algorithm allowlist (default RS256,ES256)

	// ---- Seed-on-bootstrap (peer seeding) — design spec §3 -----------------
	// When SeedServers is non-empty AND the local remotes table is empty, the
	// server bootstraps itself from these peer git-tainted servers (adopting their
	// remotes, tag projections, and taint history under a quorum) instead of
	// starting blind. See internal/seed.
	SeedServers string // comma/space-separated peer base URLs; empty ⇒ feature off
	// SeedQuorum is the minimum number of peers that must agree to adopt a fact.
	SeedQuorum int
	// SeedRemotes is an optional comma-separated glob allowlist on adopted remote URLs.
	SeedRemotes string
	// SeedConcurrency bounds the in-flight peer HTTP request fan-out.
	SeedConcurrency int
	// SeedTimeout is the per-request HTTP deadline (env GT_SEED_TIMEOUT_NS, int64-ns).
	SeedTimeout time.Duration
	// SeedInsecure allows plaintext http:// to non-loopback peers (mirrors the CLI guard).
	SeedInsecure bool
	// SeedMaxRemotes is the fail-loud ceiling on remotes in the single seed transaction.
	SeedMaxRemotes int
	// SeedMaxObservations is the fail-loud ceiling on total observations in the txn.
	SeedMaxObservations int
	// SeedMaxPages is the per-resource pagination safety bound.
	SeedMaxPages int
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
	boolean := func(key string, def bool) bool {
		v, ok := get(key)
		if !ok {
			return def
		}
		// Accept "true"/"1"/"yes" as true; anything else (incl. empty) is false.
		switch v {
		case "true", "1", "yes":
			return true
		default:
			return false
		}
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
	// dur parses a GT_*_NS int64-ns env var and returns it as a time.Duration.
	// The wire/env stays int64-ns (the unix-ns convention); only the in-Go value
	// is typed. Absent → def.
	dur := func(key string, def time.Duration) (time.Duration, error) {
		n, err := i64(key, int64(def))
		if err != nil {
			return 0, err
		}
		return time.Duration(n), nil
	}

	c := &Config{
		DBDriver:          str("GT_DB_DRIVER", "sqlite"),
		SQLitePath:        str("GT_SQLITE_PATH", ""),
		MySQLDSN:          str("GT_MYSQL_DSN", ""),
		ListenAddr:        str("GT_LISTEN_ADDR", "127.0.0.1:8080"),
		GitBin:            str("GT_GIT_BIN", "git"),
		ProtocolAllowlist: str("GT_PROTOCOL_ALLOWLIST", "https:ssh"),
		HostAllowlist:     str("GT_HOST_ALLOWLIST", ""),
		LogLevel:          str("GT_LOG_LEVEL", "info"),
		// Default empty = metrics DISABLED (no listener, no collection).
		MetricsAddr:  str("GT_METRICS_ADDR", ""),
		PprofEnabled: boolean("GT_PPROF_ENABLED", false),

		// Verify hot-path cache (default ON — spec §4.6).
		CacheEnabled: boolean("GT_CACHE_ENABLED", true),

		// Control-plane auth (default mode none = today's behavior).
		AuthMode:      str("GT_AUTH_MODE", AuthModeNone),
		APIKeys:       str("GT_API_KEYS", ""),
		APIKeysSHA256: str("GT_API_KEYS_SHA256", ""),
		BasicAuth:     str("GT_BASIC_AUTH", ""),
		JWKSURL:       str("GT_JWKS_URL", ""),
		JWTIssuer:     str("GT_JWT_ISSUER", ""),
		JWTAudience:   str("GT_JWT_AUDIENCE", ""),
		JWTAlgs:       str("GT_JWT_ALGS", "RS256,ES256"),

		// Seed-on-bootstrap (peer seeding — spec §3). Off by default (no servers).
		SeedServers:  str("GT_SEED_SERVERS", ""),
		SeedRemotes:  str("GT_SEED_REMOTES", ""),
		SeedInsecure: boolean("GT_SEED_INSECURE", false),
	}

	var err error
	if c.SyncConcurrency, err = iInt("GT_SYNC_CONCURRENCY", 4); err != nil {
		return nil, err
	}
	if c.SyncDefaultInterval, err = dur("GT_SYNC_DEFAULT_INTERVAL_NS", 5*time.Minute); err != nil {
		return nil, err
	}
	if c.SchedulerTick, err = dur("GT_SCHEDULER_TICK_NS", 5*time.Second); err != nil {
		return nil, err
	}
	if c.StalenessBudget, err = dur("GT_STALENESS_BUDGET_NS", time.Hour); err != nil {
		return nil, err
	}
	if c.GitTimeout, err = dur("GT_GIT_TIMEOUT_NS", time.Minute); err != nil {
		return nil, err
	}
	if c.CacheMaxEntries, err = iInt("GT_CACHE_MAX_ENTRIES", 100_000); err != nil {
		return nil, err
	}
	if c.CacheTTL, err = dur("GT_CACHE_TTL_NS", time.Minute); err != nil {
		return nil, err
	}

	// Seed-on-bootstrap (spec §3) numeric/duration keys.
	if c.SeedQuorum, err = iInt("GT_SEED_QUORUM", 1); err != nil {
		return nil, err
	}
	if c.SeedConcurrency, err = iInt("GT_SEED_CONCURRENCY", 8); err != nil {
		return nil, err
	}
	if c.SeedTimeout, err = dur("GT_SEED_TIMEOUT_NS", 30*time.Second); err != nil {
		return nil, err
	}
	if c.SeedMaxRemotes, err = iInt("GT_SEED_MAX_REMOTES", 5000); err != nil {
		return nil, err
	}
	if c.SeedMaxObservations, err = iInt("GT_SEED_MAX_OBSERVATIONS", 200_000); err != nil {
		return nil, err
	}
	if c.SeedMaxPages, err = iInt("GT_SEED_MAX_PAGES", 10_000); err != nil {
		return nil, err
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// SeedEnabled reports whether seed-on-bootstrap is configured (at least one peer
// server is listed). Whether it actually runs additionally depends on the local
// remotes table being empty (checked by the Seeder, spec §5).
func (c *Config) SeedEnabled() bool { return len(seedServerList(c.SeedServers)) > 0 }

// seedServerList splits a comma/space-separated peer URL list, dropping empties.
// Shared by SeedEnabled, validate, and the Seeder so they agree on the count.
func seedServerList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *Config) validate() error {
	switch c.DBDriver {
	case "sqlite":
		if c.SQLitePath == "" {
			return fmt.Errorf("%w: GT_SQLITE_PATH is required for the sqlite driver", ErrConfig)
		}
	case "mysql":
		if c.MySQLDSN == "" {
			return fmt.Errorf("%w: GT_MYSQL_DSN is required for the mysql driver", ErrConfig)
		}
	default:
		return fmt.Errorf("%w: GT_DB_DRIVER=%q unsupported (want sqlite or mysql)", ErrConfig, c.DBDriver)
	}
	if c.SyncConcurrency <= 0 {
		return fmt.Errorf("%w: GT_SYNC_CONCURRENCY=%d must be > 0", ErrConfig, c.SyncConcurrency)
	}
	if c.SyncDefaultInterval <= 0 {
		return fmt.Errorf("%w: GT_SYNC_DEFAULT_INTERVAL_NS=%d must be > 0", ErrConfig, int64(c.SyncDefaultInterval))
	}
	if c.SchedulerTick <= 0 {
		return fmt.Errorf("%w: GT_SCHEDULER_TICK_NS=%d must be > 0", ErrConfig, int64(c.SchedulerTick))
	}
	if c.GitTimeout <= 0 {
		return fmt.Errorf("%w: GT_GIT_TIMEOUT_NS=%d must be > 0", ErrConfig, int64(c.GitTimeout))
	}
	if c.StalenessBudget <= 0 {
		return fmt.Errorf("%w: GT_STALENESS_BUDGET_NS=%d must be > 0", ErrConfig, int64(c.StalenessBudget))
	}
	if c.CacheMaxEntries <= 0 {
		return fmt.Errorf("%w: GT_CACHE_MAX_ENTRIES=%d must be > 0", ErrConfig, c.CacheMaxEntries)
	}
	if c.CacheTTL < 0 {
		return fmt.Errorf("%w: GT_CACHE_TTL_NS=%d must be >= 0 (0 disables the TTL backstop)", ErrConfig, int64(c.CacheTTL))
	}
	switch c.AuthMode {
	case AuthModeNone, AuthModeAPIKey, AuthModeBasic, AuthModeJWKS:
		// Per-mode credential validation (keys/users/JWKS url+iss+aud) happens in
		// auth.FromConfig at startup, which main treats as fatal; here we only
		// reject an unknown mode value.
	default:
		return fmt.Errorf("%w: GT_AUTH_MODE=%q unsupported (want none, apikey, basic, or jwks)", ErrConfig, c.AuthMode)
	}

	// Seed-on-bootstrap validation (spec §3). Only the quorum-vs-server-count
	// constraint is gated on servers being set; the rest are always-on bounds.
	if servers := seedServerList(c.SeedServers); len(servers) > 0 {
		if c.SeedQuorum < 1 {
			return fmt.Errorf("%w: GT_SEED_QUORUM=%d must be >= 1", ErrConfig, c.SeedQuorum)
		}
		if c.SeedQuorum > len(servers) {
			return fmt.Errorf("%w: GT_SEED_QUORUM=%d exceeds the %d configured GT_SEED_SERVERS (no fact could ever be adopted)", ErrConfig, c.SeedQuorum, len(servers))
		}
	}
	if c.SeedConcurrency < 1 {
		return fmt.Errorf("%w: GT_SEED_CONCURRENCY=%d must be >= 1", ErrConfig, c.SeedConcurrency)
	}
	if c.SeedMaxRemotes < 1 {
		return fmt.Errorf("%w: GT_SEED_MAX_REMOTES=%d must be >= 1", ErrConfig, c.SeedMaxRemotes)
	}
	if c.SeedMaxObservations < 1 {
		return fmt.Errorf("%w: GT_SEED_MAX_OBSERVATIONS=%d must be >= 1", ErrConfig, c.SeedMaxObservations)
	}
	if c.SeedMaxPages < 1 {
		return fmt.Errorf("%w: GT_SEED_MAX_PAGES=%d must be >= 1", ErrConfig, c.SeedMaxPages)
	}
	return nil
}
