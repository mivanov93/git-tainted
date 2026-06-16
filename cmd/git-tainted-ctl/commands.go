// commands.go — subcommand implementations for git-tainted-ctl.
// Each runXxx function owns flag parsing for its sub-namespace and returns an
// OS exit code. Human-readable and --json output paths are both covered.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// separateFlags re-orders args so that all flags (and their values) precede
// positional arguments.  Go's flag package stops parsing at the first non-flag
// argument, so commands that accept a positional id followed by flags
// (e.g. "update 5 --enabled=false" or "add <url> --interval 5m") need the
// flags moved to the front.
//
// Heuristic: an argument that starts with "-" is a flag; the next token is its
// value if the flag has no "=" and the next token does not start with "-".
// This correctly handles both "--flag=val" and "--flag val" forms while keeping
// positional arguments (which do not start with "-") at the end.
func separateFlags(args []string) []string {
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			// If the flag does not embed its value ("--key=val"), and
			// the next token is not another flag, treat it as the value.
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
		} else {
			positionals = append(positionals, a)
		}
	}
	return append(flags, positionals...)
}

// ---- remote ----------------------------------------------------------------

func runRemote(args []string, globalJSON bool, cl *client, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printRemoteUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "add":
		return runRemoteAdd(args[1:], cl, stdout, stderr)
	case "list":
		return runRemoteList(args[1:], globalJSON, cl, stdout, stderr)
	case "get":
		return runRemoteGet(args[1:], globalJSON, cl, stdout, stderr)
	case "update":
		return runRemoteUpdate(args[1:], cl, stdout, stderr)
	case "rm":
		return runRemoteRm(args[1:], cl, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "error: unknown remote subcommand %q\n\n", args[0])
		printRemoteUsage(stderr)
		return exitUsage
	}
}

func printRemoteUsage(w io.Writer) {
	_, _ = io.WriteString(w, `Usage: git-tainted-ctl remote <subcommand> [flags]

Subcommands:
  add <url> [--interval <dur>] [--disabled]   Register a new remote
  list [--json] [--limit N] [--cursor N]       List all remotes
  get <id|url> [--json]                        Get one remote by id or URL
  update <id> [--interval <dur>] [--enabled=<bool>]  Update remote settings
  rm <id>                                      Delete (soft) a remote
`)
}

func runRemoteAdd(args []string, cl *client, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("remote add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var intervalStr string
	var disabled bool
	fs.StringVar(&intervalStr, "interval", "", "Sync interval (Go duration, e.g. 5m)")
	fs.BoolVar(&disabled, "disabled", false, "Register as paused (disabled)")
	if err := fs.Parse(separateFlags(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "error: remote add requires exactly one argument: <url>")
		return exitUsage
	}
	rawURL := fs.Arg(0)

	// Detect transport from URL.
	transport := "https"
	if strings.HasPrefix(rawURL, "ssh://") || (!strings.Contains(rawURL, "://") && strings.Contains(rawURL, "@")) {
		transport = "ssh"
	}

	req := wireCreateRemoteReq{
		URL:       rawURL,
		Transport: transport,
	}
	if intervalStr != "" {
		d, err := time.ParseDuration(intervalStr)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: invalid --interval %q: %v\n", intervalStr, err)
			return exitUsage
		}
		ns := int64(d)
		req.SyncIntervalNS = &ns
	}
	if disabled {
		f := false
		req.TaintAnyTagDeletion = &f
	}

	var out wireRemote
	ctx := context.Background()
	code, rawBody, err := cl.doJSON(ctx, "POST", "/v1/remotes", req, &out)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	if code != exitOK {
		_, _ = fmt.Fprintf(stderr, "error: server returned error: %s\n", apiError(rawBody))
		return code
	}
	_, _ = fmt.Fprintf(stdout, "created remote id=%d url=%s\n", out.ID, out.NormalizedURL)
	return exitOK
}

func runRemoteList(args []string, globalJSON bool, cl *client, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("remote list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var jsonFlag bool
	var limit int
	var cursor int64
	fs.BoolVar(&jsonFlag, "json", globalJSON, "Output JSON")
	fs.IntVar(&limit, "limit", 0, "Page size (server default if 0)")
	fs.Int64Var(&cursor, "cursor", 0, "Pagination cursor")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	path := "/v1/remotes"
	sep := "?"
	if limit > 0 {
		path += sep + fmt.Sprintf("limit=%d", limit)
		sep = "&"
	}
	if cursor > 0 {
		path += sep + fmt.Sprintf("cursor=%d", cursor)
	}

	var out wireRemoteList
	ctx := context.Background()
	code, rawBody, err := cl.doJSON(ctx, "GET", path, nil, &out)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	if code != exitOK {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", apiError(rawBody))
		return code
	}

	if jsonFlag {
		return writeJSON(stdout, stderr, out)
	}
	printRemoteTable(stdout, out.Items)
	if out.NextCursor != nil {
		_, _ = fmt.Fprintf(stdout, "(next cursor: %d)\n", *out.NextCursor)
	}
	return exitOK
}

func runRemoteGet(args []string, globalJSON bool, cl *client, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("remote get", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var jsonFlag bool
	fs.BoolVar(&jsonFlag, "json", globalJSON, "Output JSON")
	if err := fs.Parse(separateFlags(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "error: remote get requires exactly one argument: <id|url>")
		return exitUsage
	}
	arg := fs.Arg(0)

	ctx := context.Background()

	// If arg looks like an integer, use GET /v1/remotes/{id}.
	// Otherwise use GET /v1/remotes?url=<url> and pick the first item.
	if id, err := strconv.ParseInt(arg, 10, 64); err == nil {
		var out wireRemote
		code, rawBody, doErr := cl.doJSON(ctx, "GET", fmt.Sprintf("/v1/remotes/%d", id), nil, &out)
		if doErr != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", doErr)
			return exitUsage
		}
		if code != exitOK {
			_, _ = fmt.Fprintf(stderr, "error: %s\n", apiError(rawBody))
			return code
		}
		if jsonFlag {
			return writeJSON(stdout, stderr, out)
		}
		printRemoteTable(stdout, []wireRemote{out})
		return exitOK
	}

	// URL form: list with url= filter.
	path := "/v1/remotes?url=" + urlQueryEscape(arg)
	var list wireRemoteList
	code, rawBody, doErr := cl.doJSON(ctx, "GET", path, nil, &list)
	if doErr != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", doErr)
		return exitUsage
	}
	if code != exitOK {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", apiError(rawBody))
		return code
	}
	if len(list.Items) == 0 {
		_, _ = fmt.Fprintf(stderr, "error: no remote found for url %q\n", arg)
		return exitNotFound
	}
	out := list.Items[0]
	if jsonFlag {
		return writeJSON(stdout, stderr, out)
	}
	printRemoteTable(stdout, []wireRemote{out})
	return exitOK
}

func runRemoteUpdate(args []string, cl *client, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("remote update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var intervalStr string
	var enabledStr string
	fs.StringVar(&intervalStr, "interval", "", "New sync interval (Go duration)")
	fs.StringVar(&enabledStr, "enabled", "", "true=active / false=paused")
	if err := fs.Parse(separateFlags(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "error: remote update requires exactly one argument: <id>")
		return exitUsage
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: invalid id %q: %v\n", fs.Arg(0), err)
		return exitUsage
	}

	req := wireUpdateRemoteReq{}
	updated := false

	if intervalStr != "" {
		d, parseErr := time.ParseDuration(intervalStr)
		if parseErr != nil {
			_, _ = fmt.Fprintf(stderr, "error: invalid --interval %q: %v\n", intervalStr, parseErr)
			return exitUsage
		}
		ns := int64(d)
		req.SyncIntervalNS = &ns
		updated = true
	}
	if enabledStr != "" {
		switch strings.ToLower(enabledStr) {
		case "true", "1", "yes":
			s := "active"
			req.Status = &s
		case "false", "0", "no":
			s := "paused"
			req.Status = &s
		default:
			_, _ = fmt.Fprintf(stderr, "error: --enabled must be true or false\n")
			return exitUsage
		}
		updated = true
	}
	if !updated {
		_, _ = fmt.Fprintln(stderr, "error: remote update requires at least one of --interval or --enabled")
		return exitUsage
	}

	var out wireRemote
	ctx := context.Background()
	code, rawBody, doErr := cl.doJSON(ctx, "PATCH", fmt.Sprintf("/v1/remotes/%d", id), req, &out)
	if doErr != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", doErr)
		return exitUsage
	}
	if code != exitOK {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", apiError(rawBody))
		return code
	}
	_, _ = fmt.Fprintf(stdout, "updated remote id=%d status=%s\n", out.ID, out.Status)
	return exitOK
}

func runRemoteRm(args []string, cl *client, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("remote rm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(separateFlags(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "error: remote rm requires exactly one argument: <id>")
		return exitUsage
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: invalid id %q: %v\n", fs.Arg(0), err)
		return exitUsage
	}

	ctx := context.Background()
	code, rawBody, doErr := cl.doJSON(ctx, "DELETE", fmt.Sprintf("/v1/remotes/%d", id), nil, nil)
	if doErr != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", doErr)
		return exitUsage
	}
	if code != exitOK {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", apiError(rawBody))
		return code
	}
	_, _ = fmt.Fprintf(stdout, "deleted remote id=%d\n", id)
	return exitOK
}

// ---- sync ------------------------------------------------------------------

func runSync(args []string, cl *client, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "error: sync requires exactly one argument: <id>")
		return exitUsage
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: invalid id %q: %v\n", fs.Arg(0), err)
		return exitUsage
	}

	ctx := context.Background()
	code, rawBody, doErr := cl.doJSON(ctx, "POST", fmt.Sprintf("/v1/remotes/%d/sync", id), nil, nil)
	if doErr != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", doErr)
		return exitUsage
	}
	if code != exitOK {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", apiError(rawBody))
		return code
	}
	_, _ = fmt.Fprintf(stdout, "sync queued for remote id=%d (202 Accepted)\n", id)
	return exitOK
}

// ---- syncs -----------------------------------------------------------------

func runSyncs(args []string, globalJSON bool, cl *client, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("syncs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var jsonFlag bool
	var limit int
	fs.BoolVar(&jsonFlag, "json", globalJSON, "Output JSON")
	fs.IntVar(&limit, "limit", 0, "Page size (server default if 0)")
	if err := fs.Parse(separateFlags(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "error: syncs requires exactly one argument: <id>")
		return exitUsage
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: invalid id %q: %v\n", fs.Arg(0), err)
		return exitUsage
	}

	path := fmt.Sprintf("/v1/remotes/%d/syncs", id)
	if limit > 0 {
		path += fmt.Sprintf("?limit=%d", limit)
	}

	var out wireSyncAuditList
	ctx := context.Background()
	code, rawBody, doErr := cl.doJSON(ctx, "GET", path, nil, &out)
	if doErr != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", doErr)
		return exitUsage
	}
	if code != exitOK {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", apiError(rawBody))
		return code
	}
	if jsonFlag {
		return writeJSON(stdout, stderr, out)
	}
	printSyncTable(stdout, out.Items)
	if out.NextCursor != nil {
		_, _ = fmt.Fprintf(stdout, "(next cursor: %d)\n", *out.NextCursor)
	}
	return exitOK
}

// ---- tags ------------------------------------------------------------------

func runTags(args []string, globalJSON bool, cl *client, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tags", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var jsonFlag bool
	fs.BoolVar(&jsonFlag, "json", globalJSON, "Output JSON")
	if err := fs.Parse(separateFlags(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "error: tags requires exactly one argument: <id>")
		return exitUsage
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: invalid id %q: %v\n", fs.Arg(0), err)
		return exitUsage
	}

	var out wireTagList
	ctx := context.Background()
	code, rawBody, doErr := cl.doJSON(ctx, "GET", fmt.Sprintf("/v1/remotes/%d/tags", id), nil, &out)
	if doErr != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", doErr)
		return exitUsage
	}
	if code != exitOK {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", apiError(rawBody))
		return code
	}
	if jsonFlag {
		return writeJSON(stdout, stderr, out)
	}
	printTagTable(stdout, out.Items)
	if out.NextCursor != nil {
		_, _ = fmt.Fprintf(stdout, "(next cursor: %d)\n", *out.NextCursor)
	}
	return exitOK
}

// ---- taint -----------------------------------------------------------------

func runTaint(args []string, globalJSON bool, cl *client, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "error: taint requires a subcommand: list|ack")
		return exitUsage
	}
	switch args[0] {
	case "list":
		return runTaintList(args[1:], globalJSON, cl, stdout, stderr)
	case "ack":
		return runTaintAck(args[1:], cl, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "error: unknown taint subcommand %q\n", args[0])
		return exitUsage
	}
}

func runTaintList(args []string, globalJSON bool, cl *client, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("taint list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var jsonFlag bool
	fs.BoolVar(&jsonFlag, "json", globalJSON, "Output JSON")
	if err := fs.Parse(separateFlags(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "error: taint list requires exactly one argument: <id>")
		return exitUsage
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: invalid id %q: %v\n", fs.Arg(0), err)
		return exitUsage
	}

	var out wireTaintEventList
	ctx := context.Background()
	code, rawBody, doErr := cl.doJSON(ctx, "GET", fmt.Sprintf("/v1/remotes/%d/taint-events", id), nil, &out)
	if doErr != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", doErr)
		return exitUsage
	}
	if code != exitOK {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", apiError(rawBody))
		return code
	}
	if jsonFlag {
		return writeJSON(stdout, stderr, out)
	}
	printTaintTable(stdout, out.Items)
	if out.NextCursor != nil {
		_, _ = fmt.Fprintf(stdout, "(next cursor: %d)\n", *out.NextCursor)
	}
	return exitOK
}

func runTaintAck(args []string, cl *client, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("taint ack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var note string
	var by string
	fs.StringVar(&note, "note", "", "Acknowledgement note")
	fs.StringVar(&by, "by", "", "Identity acknowledging the event (required)")
	if err := fs.Parse(separateFlags(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 2 {
		_, _ = fmt.Fprintln(stderr, "error: taint ack requires two arguments: <remoteId> <eventId>")
		return exitUsage
	}
	remoteID, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: invalid remoteId %q: %v\n", fs.Arg(0), err)
		return exitUsage
	}
	eventID, err := strconv.ParseInt(fs.Arg(1), 10, 64)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: invalid eventId %q: %v\n", fs.Arg(1), err)
		return exitUsage
	}
	if by == "" {
		_, _ = fmt.Fprintln(stderr, "error: --by is required for taint ack")
		return exitUsage
	}

	req := wireAckReq{AckedBy: by, AckNote: note}
	path := fmt.Sprintf("/v1/remotes/%d/taint-events/%d/ack", remoteID, eventID)

	ctx := context.Background()
	code, rawBody, doErr := cl.doJSON(ctx, "POST", path, req, nil)
	if doErr != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", doErr)
		return exitUsage
	}
	if code != exitOK {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", apiError(rawBody))
		return code
	}
	_, _ = fmt.Fprintf(stdout, "taint event %d acknowledged by %q\n", eventID, by)
	return exitOK
}

// ---- output helpers --------------------------------------------------------

func writeJSON(w io.Writer, stderr io.Writer, v any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: encoding JSON: %v\n", err)
		return exitUsage
	}
	return exitOK
}

func printRemoteTable(w io.Writer, remotes []wireRemote) {
	_, _ = fmt.Fprintf(w, "%-6s  %-8s  %-10s  %s\n", "ID", "STATUS", "TRANSPORT", "URL")
	for _, r := range remotes {
		_, _ = fmt.Fprintf(w, "%-6d  %-8s  %-10s  %s\n", r.ID, r.Status, r.Transport, r.NormalizedURL)
	}
}

func printSyncTable(w io.Writer, syncs []wireSyncEntry) {
	_, _ = fmt.Fprintf(w, "%-6s  %-8s  %-9s  %-4s  %-4s  %s\n",
		"ID", "STATUS", "TRIGGER", "SEEN", "CHGD", "STARTED")
	for _, s := range syncs {
		t := time.Unix(0, s.StartedNS).UTC().Format(time.RFC3339)
		_, _ = fmt.Fprintf(w, "%-6d  %-8s  %-9s  %-4d  %-4d  %s\n",
			s.ID, s.Status, s.Trigger, s.TagsSeen, s.TagsChanged, t)
	}
}

func printTagTable(w io.Writer, tags []wireTag) {
	_, _ = fmt.Fprintf(w, "%-6s  %-8s  %-8s  %s\n", "ID", "TAINTED", "DELETED", "TAG")
	for _, t := range tags {
		tainted := boolStr(t.Tainted)
		deleted := boolStr(t.Deleted)
		_, _ = fmt.Fprintf(w, "%-6d  %-8s  %-8s  %s\n", t.ID, tainted, deleted, t.TagName)
	}
}

func printTaintTable(w io.Writer, events []wireTaintEvent) {
	_, _ = fmt.Fprintf(w, "%-6s  %-6s  %-24s  %-26s  %s\n",
		"ID", "REF", "REASON", "DETECTED", "ACKED_BY")
	for _, e := range events {
		det := time.Unix(0, e.DetectedAtNS).UTC().Format(time.RFC3339)
		ackedBy := "-"
		if e.AckedBy != nil {
			ackedBy = *e.AckedBy
		}
		_, _ = fmt.Fprintf(w, "%-6d  %-6d  %-24s  %-26s  %s\n",
			e.ID, e.RefID, e.Reason, det, ackedBy)
	}
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// urlQueryEscape percent-encodes s for use as a query param value.
// Uses net/url.QueryEscape from the standard library.
func urlQueryEscape(s string) string {
	// Inline to avoid importing net/url at package level when not needed.
	// However we already import net in client.go; just use fmt.Sprintf workaround.
	// Actually using the standard approach:
	var sb strings.Builder
	for _, b := range []byte(s) {
		if isURLSafe(b) {
			sb.WriteByte(b)
		} else {
			_, _ = fmt.Fprintf(&sb, "%%%02X", b)
		}
	}
	return sb.String()
}

func isURLSafe(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '-' || b == '_' || b == '.' || b == '~' ||
		b == ':' || b == '/' || b == '@' // keep URL structure chars unencoded
}
