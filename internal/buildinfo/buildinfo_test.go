package buildinfo

import "testing"

func TestString_InjectedVersionWins(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "v1.2.3"
	if got := String(); got != "v1.2.3" {
		t.Errorf("String() = %q, want v1.2.3", got)
	}
}

func TestString_DevSentinelFallsBack(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	// "dev" (and whitespace-padded variants) is the not-injected sentinel and
	// must NOT be returned verbatim; String falls back to build info (non-empty).
	for _, v := range []string{"", "  ", "dev", "  dev  "} {
		Version = v
		if got := String(); got == "" {
			t.Errorf("String() returned empty for Version=%q", v)
		}
	}
}
