package git

import (
	"errors"
	"strings"
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
)

func TestValidateURL_Rejects(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", 5000)
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"file_scheme", "file:///etc/passwd"},
		{"git_scheme", "git://example.com/repo.git"},
		{"ext_transport", "ext::sh -c id"},
		{"fd_transport", "fd::7"},
		{"leading_dash", "-oProxyCommand=id"},
		{"ssh_leading_dash_host", "ssh://-oProxyCommand=id/repo"},
		{"control_char_nl", "https://example.com/repo\n.git"},
		{"control_char_nul", "https://example.com/repo\x00.git"},
		{"control_char_tab", "https://example.com/\trepo.git"},
		{"too_long", long},
		{"http_plain", "http://example.com/repo.git"},
		{"scp_leading_dash_user", "-x@host:owner/repo"},
		{"no_host_https", "https:///repo.git"},
		{"space_in_url", "https://example.com/ repo.git"},
		{"bare_word", "justsometext"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := ValidateURL(tc.in)
			if !errors.Is(err, model.ErrBadURL) {
				t.Fatalf("ValidateURL(%q) err = %v, want wraps ErrBadURL", tc.in, err)
			}
		})
	}
}

func TestValidateURL_Accepts(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		wantTrans model.Transport
		wantNorm  string
	}{
		{"https_basic", "https://example.com/owner/repo.git", model.TransportHTTPS, "https://example.com/owner/repo.git"},
		{"https_uppercase_host", "https://Example.COM/Owner/Repo.git", model.TransportHTTPS, "https://example.com/Owner/Repo.git"},
		{"https_trailing_slash", "https://example.com/owner/repo/", model.TransportHTTPS, "https://example.com/owner/repo"},
		{"https_default_port_stripped", "https://example.com:443/owner/repo.git", model.TransportHTTPS, "https://example.com/owner/repo.git"},
		{"ssh_scheme", "ssh://git@example.com/owner/repo.git", model.TransportSSH, "ssh://git@example.com/owner/repo.git"},
		{"ssh_scheme_default_port", "ssh://git@example.com:22/owner/repo.git", model.TransportSSH, "ssh://git@example.com/owner/repo.git"},
		{"scp_like", "git@example.com:owner/repo.git", model.TransportSSH, "ssh://git@example.com/owner/repo.git"},
		{"scp_uppercase_host", "git@Example.com:Owner/Repo.git", model.TransportSSH, "ssh://git@example.com/Owner/Repo.git"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotURL, gotNorm, gotTrans, err := ValidateURL(tc.in)
			if err != nil {
				t.Fatalf("ValidateURL(%q) unexpected err = %v", tc.in, err)
			}
			if gotURL != tc.in {
				t.Errorf("url = %q, want %q (verbatim original)", gotURL, tc.in)
			}
			if gotTrans != tc.wantTrans {
				t.Errorf("transport = %q, want %q", gotTrans, tc.wantTrans)
			}
			if gotNorm != tc.wantNorm {
				t.Errorf("normalized = %q, want %q", gotNorm, tc.wantNorm)
			}
		})
	}
}

func TestValidateURL_NormalizeIsStableUnderRepeat(t *testing.T) {
	_, norm1, _, err := ValidateURL("git@example.com:Owner/Repo.git")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// Re-validating the normalized form yields the same normalized form (idempotent).
	_, norm2, _, err := ValidateURL(norm1)
	if err != nil {
		t.Fatalf("unexpected err re-validating %q: %v", norm1, err)
	}
	if norm1 != norm2 {
		t.Fatalf("normalize not idempotent: %q -> %q", norm1, norm2)
	}
}
