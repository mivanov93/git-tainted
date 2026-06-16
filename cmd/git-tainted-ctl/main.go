// Command git-tainted-ctl is the git-tainted admin/operator CLI.
// It registers and configures remotes, drives on-demand syncs, and manages
// taint-event acknowledgements against the git-tainted server control API.
//
// This binary has no SQLite/server dependencies — just an HTTP client.
// It intentionally does NOT import internal/api/oapi; wire shapes are thin
// local structs matching the JSON schema.
//
// Usage:
//
//	git-tainted-ctl [global-flags] <command> [flags] [args]
//
// Commands:
//
//	remote add <url> [--interval <dur>] [--disabled]
//	remote list [--json] [--limit N] [--cursor N]
//	remote get <id|url> [--json]
//	remote update <id> [--interval <dur>] [--enabled=<bool>]
//	remote rm <id>
//	sync <id>
//	syncs <id> [--limit N] [--json]
//	tags <id> [--json]
//	taint list <id> [--json]
//	taint ack <id> <eventId> [--note <s>] [--by <s>]
//
// Global flags:
//
//	--server <url>     Server base URL (env: GT_CTL_SERVER, default: http://127.0.0.1:8080)
//	--api-key <key>    API key auth (env: GT_API_KEY)
//	--token <jwt>      Bearer JWT auth (env: GT_TOKEN)
//	--basic <u:p>      Basic auth user:pass (env: GT_BASIC_AUTH)
//	--timeout <dur>    HTTP timeout (default: 10s)
//	--insecure         Allow plaintext http:// to non-loopback (env: GT_CTL_INSECURE)
//	--json             Output machine-readable JSON
//	--version, -v      Print version and exit
//	--help, -h         Print usage and exit
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mivanov93/git-tainted/internal/buildinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Environ(), os.Stdout, os.Stderr))
}

// run is the testable entry point. Returns an OS exit code.
func run(args []string, environ []string, stdout, stderr io.Writer) int {
	// Top-level flag set — parses global flags before the subcommand.
	fs := flag.NewFlagSet("git-tainted-ctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printTopUsage(stderr) }

	var (
		serverFlag  string
		apiKeyFlag  string
		tokenFlag   string
		basicFlag   string
		timeoutFlag string
		insecure    bool
		jsonFlag    bool
		versionFlag bool
	)
	fs.StringVar(&serverFlag, "server", "", "Server base URL (env: GT_CTL_SERVER)")
	fs.StringVar(&apiKeyFlag, "api-key", "", "API key (env: GT_API_KEY)")
	fs.StringVar(&tokenFlag, "token", "", "Bearer JWT (env: GT_TOKEN)")
	fs.StringVar(&basicFlag, "basic", "", "Basic auth user:pass (env: GT_BASIC_AUTH)")
	fs.StringVar(&timeoutFlag, "timeout", "10s", "HTTP timeout (default: 10s)")
	fs.BoolVar(&insecure, "insecure", false, "Allow plaintext http:// to non-loopback (env: GT_CTL_INSECURE)")
	fs.BoolVar(&jsonFlag, "json", false, "Output machine-readable JSON")
	fs.BoolVar(&versionFlag, "version", false, "Print version and exit")
	fs.BoolVar(&versionFlag, "v", false, "Print version and exit (shorthand)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if versionFlag {
		_, _ = fmt.Fprintf(stdout, "git-tainted-ctl %s\n", buildinfo.String())
		return 0
	}

	// Resolve global config from flags → env.
	server := serverFlag
	if server == "" {
		server = envValue(environ, "GT_CTL_SERVER")
	}
	if server == "" {
		server = "http://127.0.0.1:8080"
	}

	if !insecure {
		insecure = envBool(environ, "GT_CTL_INSECURE")
	}

	// Resolve auth credentials: explicit flag wins over env.
	authCreds := resolveAuth(apiKeyFlag, tokenFlag, basicFlag, environ)

	// Parse timeout.
	timeout := 10 * time.Second
	if timeoutFlag != "" {
		d, err := time.ParseDuration(timeoutFlag)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: invalid --timeout %q: %v\n", timeoutFlag, err)
			return 2
		}
		timeout = d
	}

	// Validate server URL (loopback guard).
	if err := checkServerURL(server, insecure); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	sub := fs.Args()
	if len(sub) == 0 {
		printTopUsage(stderr)
		return 2
	}

	cl := &client{
		server:  server,
		auth:    authCreds,
		timeout: timeout,
	}

	switch sub[0] {
	case "remote":
		return runRemote(sub[1:], jsonFlag, cl, stdout, stderr)
	case "sync":
		return runSync(sub[1:], cl, stdout, stderr)
	case "syncs":
		return runSyncs(sub[1:], jsonFlag, cl, stdout, stderr)
	case "tags":
		return runTags(sub[1:], jsonFlag, cl, stdout, stderr)
	case "taint":
		return runTaint(sub[1:], jsonFlag, cl, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "error: unknown command %q\n\n", sub[0])
		printTopUsage(stderr)
		return 2
	}
}

func printTopUsage(w io.Writer) {
	_, _ = io.WriteString(w, `Usage: git-tainted-ctl [global-flags] <command> [flags] [args]

Commands:
  remote add <url> [--interval <dur>] [--disabled]   Register a new remote
  remote list [--json] [--limit N] [--cursor N]       List all remotes
  remote get <id|url> [--json]                        Get one remote
  remote update <id> [--interval <dur>] [--enabled=<bool>]  Update settings
  remote rm <id>                                      Delete a remote
  sync <id>                                           Trigger on-demand sync (202)
  syncs <id> [--limit N] [--json]                     List sync audit rows
  tags <id> [--json]                                  List tag projections
  taint list <id> [--json]                            List taint events
  taint ack <id> <eventId> [--note <s>] [--by <s>]   Acknowledge a taint event

Global flags:
  --server <url>     Server base URL (env: GT_CTL_SERVER, default: http://127.0.0.1:8080)
  --api-key <key>    API key auth (env: GT_API_KEY)
  --token <jwt>      Bearer JWT auth (env: GT_TOKEN)
  --basic <u:p>      Basic auth user:pass (env: GT_BASIC_AUTH)
  --timeout <dur>    HTTP timeout (default: 10s)
  --insecure         Allow plaintext http:// to non-loopback (env: GT_CTL_INSECURE)
  --json             Output machine-readable JSON
  --version, -v      Print version and exit
  --help, -h         Print this help and exit

Exit codes:
  0   ok
  2   usage / transport / parse error
  3   not found (404)
  4   unauthorized / forbidden (401/403)
  5   conflict (409)
  6   server error (5xx)
`)
}
