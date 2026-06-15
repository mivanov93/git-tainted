package config

import (
	"io"
	"log/slog"
	"strings"
)

// ParseLevel maps a TL_LOG_LEVEL string to a slog.Level. Unknown/empty → info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// NewLogger builds the service's structured JSON slog.Logger writing to w at
// the given level. JSON is the only log format (no fmt.Println anywhere; secrets
// are never logged and oids are logged as hex, per the project conventions).
func NewLogger(w io.Writer, level string) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: ParseLevel(level)})
	return slog.New(h)
}
