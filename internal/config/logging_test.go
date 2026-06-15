package config

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"INFO", slog.LevelInfo},
		{"unknown", slog.LevelInfo},
		{"", slog.LevelInfo},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := ParseLevel(tc.in); got != tc.want {
				t.Errorf("ParseLevel(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNewLoggerEmitsJSONAtLevel(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, "warn")

	log.Info("suppressed")
	if buf.Len() != 0 {
		t.Fatalf("info line should be suppressed at warn level, got: %s", buf.String())
	}

	log.Warn("kept", "k", "v")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not JSON: %v (raw=%q)", err, buf.String())
	}
	if rec["msg"] != "kept" {
		t.Errorf("msg = %v, want kept", rec["msg"])
	}
	if rec["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", rec["level"])
	}
	if rec["k"] != "v" {
		t.Errorf("attr k = %v, want v", rec["k"])
	}
}
