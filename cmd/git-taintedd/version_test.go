package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHandleFlags(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		wantHandled bool
		wantCode    int
		wantStdout  string // substring expected in stdout (empty = don't check)
	}{
		{"no args runs server", nil, false, 0, ""},
		{"version long", []string{"--version"}, true, 0, "git-taintedd "},
		{"version short", []string{"-v"}, true, 0, "git-taintedd "},
		{"help long", []string{"--help"}, true, 0, "Usage:"},
		{"help short", []string{"-h"}, true, 0, "Usage:"},
		{"unknown flag", []string{"--nope"}, true, 2, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code, handled := handleFlags(tc.args, &out, &errb)
			if handled != tc.wantHandled || code != tc.wantCode {
				t.Fatalf("handleFlags(%v) = (%d, %v), want (%d, %v)", tc.args, code, handled, tc.wantCode, tc.wantHandled)
			}
			if tc.wantStdout != "" && !strings.Contains(out.String(), tc.wantStdout) {
				t.Errorf("handleFlags(%v) stdout %q does not contain %q", tc.args, out.String(), tc.wantStdout)
			}
		})
	}
}
