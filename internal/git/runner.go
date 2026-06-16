package git

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/mivanov93/git-tainted/internal/model"
)

// Config configures the hardened git runner (used by NewExecGitRunner).
type Config struct {
	GitBin string
	// Timeout is the per-call deadline; 0 = no deadline.
	Timeout time.Duration
	// ProtocolAllow overrides GIT_ALLOW_PROTOCOL. Empty = production default "https:ssh".
	// Pass "http:https:ssh" for the loopback fixture server in tests.
	ProtocolAllow string
}

// execGitRunner is the hardened model.GitRunner over the system git binary.
type execGitRunner struct {
	gitBin        string
	timeout       time.Duration
	allowProtocol string
}

// NewExecGitRunner constructs the hardened GitRunner from a Config.
func NewExecGitRunner(cfg Config) model.GitRunner {
	if cfg.GitBin == "" {
		cfg.GitBin = "git"
	}
	return &execGitRunner{
		gitBin:        cfg.GitBin,
		timeout:       cfg.Timeout,
		allowProtocol: cfg.ProtocolAllow,
	}
}

// NewRunnerWithProtocols is like NewExecGitRunner but allows overriding the protocol
// allowlist for test fixture servers that serve over plain HTTP.
// Production code must never call this with allowProtocol != "https:ssh".
func NewRunnerWithProtocols(gitBin string, timeout time.Duration, allowProtocol string) model.GitRunner {
	if gitBin == "" {
		gitBin = "git"
	}
	return &execGitRunner{gitBin: gitBin, timeout: timeout, allowProtocol: allowProtocol}
}

// hardenedArgv builds the global-hardening argv prefix (§5) followed by the
// subcommand and its args. Global -c flags MUST precede the subcommand.
func hardenedArgv(sub string, args ...string) []string {
	argv := []string{
		"--no-replace-objects",
		"-c", "core.useReplaceRefs=false",
		"-c", "core.hooksPath=/dev/null",
		"-c", "protocol.file.allow=never",
		"-c", "protocol.ext.allow=never",
		"-c", "transfer.fsckObjects=true",
		"-c", "receive.fsckObjects=true",
		sub,
	}
	return append(argv, args...)
}

// hardenedEnvWithProtocol returns the controlled environment for git calls.
// allowProtocol empty = production default "https:ssh".
func hardenedEnvWithProtocol(auth *model.MaterializedAuth, allowProtocol string) []string {
	if allowProtocol == "" {
		allowProtocol = "https:ssh"
	}
	env := []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ALLOW_PROTOCOL=" + allowProtocol,
		"GIT_PROTOCOL_FROM_USER=0",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_ASKPASS=",
		"GIT_OPTIONAL_LOCKS=0",
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}
	if auth != nil {
		if auth.GitConfigGlobal != "" {
			env = append(env, "GIT_CONFIG_GLOBAL="+auth.GitConfigGlobal)
		} else {
			env = append(env, "GIT_CONFIG_GLOBAL=/dev/null")
		}
		if auth.SSHCommand != "" {
			env = append(env, "GIT_SSH_COMMAND="+auth.SSHCommand)
		}
		env = append(env, auth.EnvOverlay...)
	} else {
		env = append(env, "GIT_CONFIG_GLOBAL=/dev/null")
	}
	return env
}

// run execs git with the hardened argv+env under a timeout-bounded context.
func (r *execGitRunner) run(ctx context.Context, auth *model.MaterializedAuth, dir string, argv []string) ([]byte, error) {
	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, r.gitBin, argv...) //nolint:gosec // gitBin is a controlled path, not user input
	cmd.Env = hardenedEnvWithProtocol(auth, r.allowProtocol)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("git %v: %w", argv[len(argv)-2:], ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("git %s failed: %w: %s", argv[0], err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// LsRemote runs hardened `git ls-remote --tags <url>` and parses tags only (§6).
func (r *execGitRunner) LsRemote(ctx context.Context, rawURL string, auth *model.MaterializedAuth) ([]model.LsRemoteRef, error) {
	argv := hardenedArgv("ls-remote", "--tags", "--end-of-options", rawURL)
	out, err := r.run(ctx, auth, "", argv)
	if err != nil {
		return nil, fmt.Errorf("ls-remote: %w", err)
	}
	algo := detectAlgoFromLsRemote(out)
	if !algo.Valid() {
		// Empty repo — no refs yet; return empty list.
		return nil, nil
	}
	return ParseLsRemote(out, algo)
}
