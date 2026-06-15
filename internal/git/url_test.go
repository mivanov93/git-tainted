package git

import (
	"errors"
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
)

// TestNormalizeURL tests the NormalizeURL compatibility wrapper (delegates to ValidateURL).
// Phase-2 replaces the Phase-1 URL implementation; .git suffix is preserved (not stripped)
// since the Phase-2 foundation spec stores the verbatim normalized form.
func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		// HTTPS normalizations
		{
			name:  "https lowercase host",
			input: "https://GitHub.COM/org/repo.git",
			want:  "https://github.com/org/repo.git",
		},
		{
			name:  "https trailing slash stripped",
			input: "https://github.com/org/repo/",
			want:  "https://github.com/org/repo",
		},
		{
			name:  "https no .git suffix stays as-is",
			input: "https://github.com/org/repo",
			want:  "https://github.com/org/repo",
		},
		{
			name:  "https .git suffix preserved in normalized form",
			input: "https://github.com/org/repo.git",
			want:  "https://github.com/org/repo.git",
		},
		// SSH scp-like
		{
			name:  "ssh scp-like git@",
			input: "git@github.com:org/repo.git",
			want:  "ssh://git@github.com/org/repo.git",
		},
		{
			name:  "ssh:// scheme",
			input: "ssh://git@github.com/org/repo.git",
			want:  "ssh://git@github.com/org/repo.git",
		},
		// Rejected transports
		{
			name:    "file:// rejected",
			input:   "file:///tmp/repo",
			wantErr: model.ErrBadURL,
		},
		{
			name:    "git:// rejected",
			input:   "git://github.com/org/repo",
			wantErr: model.ErrBadURL,
		},
		{
			name:    "ext:: rejected",
			input:   "ext::git-remote-ext %S repo",
			wantErr: model.ErrBadURL,
		},
		{
			name:    "fd:: rejected",
			input:   "fd::0",
			wantErr: model.ErrBadURL,
		},
		// Option injection
		{
			name:    "leading dash in host rejected",
			input:   "https://-evil.com/repo",
			wantErr: model.ErrBadURL,
		},
		// Control characters
		{
			name:    "control char in URL rejected",
			input:   "https://github.com/org/re\x00po",
			wantErr: model.ErrBadURL,
		},
		// Length cap
		{
			name:    "URL exceeding 2048 chars rejected",
			input:   "https://github.com/" + string(make([]byte, 2048)),
			wantErr: model.ErrBadURL,
		},
		// Empty input
		{
			name:    "empty string rejected",
			input:   "",
			wantErr: model.ErrBadURL,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeURL(tc.input)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.want {
				t.Errorf("NormalizeURL(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeURLTransport(t *testing.T) {
	_, err := NormalizeURL("https://github.com/org/repo.git")
	if err != nil {
		t.Fatalf("https should be accepted: %v", err)
	}
	_, err = NormalizeURL("ssh://git@github.com/org/repo")
	if err != nil {
		t.Fatalf("ssh:// should be accepted: %v", err)
	}
}
