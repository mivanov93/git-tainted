package git

import (
	"strings"
	"testing"

	"github.com/mivanov93/git-tainted/internal/model"
)

func hasEnv(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

func TestHardenedEnv(t *testing.T) {
	auth := (*model.MaterializedAuth)(nil)
	env := hardenedEnvWithProtocol(auth, "https:ssh")
	must := []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ALLOW_PROTOCOL=https:ssh",
		"GIT_PROTOCOL_FROM_USER=0",
		"GIT_LFS_SKIP_SMUDGE=1",
	}
	for _, kv := range must {
		if !hasEnv(env, kv) {
			t.Errorf("hardenedEnv missing %q\nenv=%v", kv, env)
		}
	}
	// must never leak an interactive askpass/prompt
	for _, e := range env {
		if strings.HasPrefix(e, "GIT_ASKPASS=") && e != "GIT_ASKPASS=" {
			t.Errorf("GIT_ASKPASS must be empty, got %q", e)
		}
	}
}

func TestHardenedArgv(t *testing.T) {
	argv := hardenedArgv("ls-remote", "--", "https://example.com/r.git")
	joined := strings.Join(argv, " ")
	wantFlags := []string{
		"--no-replace-objects",
		"-c core.useReplaceRefs=false",
		"-c core.hooksPath=/dev/null",
		"-c protocol.file.allow=never",
		"-c protocol.ext.allow=never",
	}
	for _, f := range wantFlags {
		if !strings.Contains(joined, f) {
			t.Errorf("hardenedArgv missing %q\nargv=%v", f, argv)
		}
	}
	// global hardening flags must precede the subcommand
	subIdx, urlIdx := -1, -1
	for i, a := range argv {
		if a == "ls-remote" {
			subIdx = i
		}
		if a == "https://example.com/r.git" {
			urlIdx = i
		}
	}
	if subIdx < 0 || urlIdx < 0 || subIdx > urlIdx {
		t.Fatalf("argv ordering wrong: sub=%d url=%d argv=%v", subIdx, urlIdx, argv)
	}
	// the global -c flags must come BEFORE the subcommand
	for i, a := range argv {
		if a == "--no-replace-objects" && i > subIdx {
			t.Errorf("--no-replace-objects must precede subcommand")
		}
	}
}
