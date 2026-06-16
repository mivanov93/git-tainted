package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLI_Version(t *testing.T) {
	for _, arg := range []string{"--version", "-v"} {
		var out, errb bytes.Buffer
		code := run([]string{arg}, nil, &out, &errb)
		if code != 0 {
			t.Errorf("run(%q) exit = %d, want 0; stderr=%q", arg, code, errb.String())
		}
		if !strings.Contains(out.String(), "git-tainted ") {
			t.Errorf("run(%q) stdout %q does not contain a version line", arg, out.String())
		}
	}
}

func TestCLI_Help(t *testing.T) {
	for _, arg := range []string{"--help", "-h"} {
		var out, errb bytes.Buffer
		if code := run([]string{arg}, nil, &out, &errb); code != 0 {
			t.Errorf("run(%q) exit = %d, want 0", arg, code)
		}
	}
}
