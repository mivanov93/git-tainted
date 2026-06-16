// client.go — HTTP client + auth helpers + transport guard for git-tainted-ctl.
// Intentionally does NOT import internal/api/oapi; wire shapes are thin local
// structs. The checkServerURL / isLoopbackHost helpers are copied from
// cmd/git-tainted (must not share code across cmd/ packages).
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// exitCode constants per §3.4.
const (
	exitOK          = 0
	exitUsage       = 2
	exitNotFound    = 3
	exitUnauth      = 4
	exitConflict    = 5
	exitServerError = 6
)

// authMode describes which credential to send.
type authMode int

const (
	authNone     authMode = iota
	authAPIKey            // Authorization: Bearer <key> + X-Api-Key: <key>
	authToken             // Authorization: Bearer <jwt>
	authBasic             // Authorization: Basic <b64(user:pass)>
)

// authCreds holds the resolved credentials.
type authCreds struct {
	mode  authMode
	value string // raw key, jwt, or user:pass
}

// resolveAuth picks auth from explicit flags first, then env.
// Priority: api-key > token > basic > none.
func resolveAuth(apiKeyFlag, tokenFlag, basicFlag string, environ []string) authCreds {
	if apiKeyFlag != "" {
		return authCreds{mode: authAPIKey, value: apiKeyFlag}
	}
	if tokenFlag != "" {
		return authCreds{mode: authToken, value: tokenFlag}
	}
	if basicFlag != "" {
		return authCreds{mode: authBasic, value: basicFlag}
	}
	if v := envValue(environ, "GT_API_KEY"); v != "" {
		return authCreds{mode: authAPIKey, value: v}
	}
	if v := envValue(environ, "GT_TOKEN"); v != "" {
		return authCreds{mode: authToken, value: v}
	}
	if v := envValue(environ, "GT_BASIC_AUTH"); v != "" {
		return authCreds{mode: authBasic, value: v}
	}
	return authCreds{mode: authNone}
}

// applyAuth adds the appropriate Authorization (and X-Api-Key) headers.
func (a authCreds) applyAuth(req *http.Request) {
	switch a.mode {
	case authAPIKey:
		req.Header.Set("Authorization", "Bearer "+a.value)
		req.Header.Set("X-Api-Key", a.value)
	case authToken:
		req.Header.Set("Authorization", "Bearer "+a.value)
	case authBasic:
		encoded := base64.StdEncoding.EncodeToString([]byte(a.value))
		req.Header.Set("Authorization", "Basic "+encoded)
	}
}

// client is the thin HTTP client used by all subcommands.
type client struct {
	server  string
	auth    authCreds
	timeout time.Duration
	// httpClient is injectable for tests; nil uses the default transport.
	httpClient *http.Client
}

func (c *client) newHTTPClient() *http.Client {
	if c.httpClient != nil {
		return c.httpClient
	}
	return &http.Client{Timeout: c.timeout}
}

// do performs an HTTP request and returns the raw response.
// Caller is responsible for closing resp.Body.
func (c *client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	rawURL := strings.TrimRight(c.server, "/") + path

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshalling request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	c.auth.applyAuth(req)

	resp, err := c.newHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling server: %w", err)
	}
	return resp, nil
}

// doJSON performs a request, decodes a JSON response body into out (if non-nil),
// and maps the HTTP status to an exit code. Returns (exitCode, error).
// A non-OK HTTP status is NOT returned as an error — the caller checks exitCode.
func (c *client) doJSON(ctx context.Context, method, path string, reqBody, out any) (int, string, error) {
	resp, err := c.do(ctx, method, path, reqBody)
	if err != nil {
		return exitUsage, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return exitUsage, "", fmt.Errorf("reading response: %w", err)
	}

	code := httpStatusToExitCode(resp.StatusCode)
	if out != nil && resp.StatusCode/100 == 2 {
		if err := json.Unmarshal(rawBody, out); err != nil {
			return exitUsage, "", fmt.Errorf("parsing response: %w", err)
		}
	}
	return code, string(rawBody), nil
}

// apiError extracts the "error" field from a JSON error body.
func apiError(rawBody string) string {
	var e struct {
		Error string `json:"error"`
	}
	if jerr := json.Unmarshal([]byte(rawBody), &e); jerr == nil && e.Error != "" {
		return e.Error
	}
	if rawBody != "" {
		return rawBody
	}
	return "unknown error"
}

// httpStatusToExitCode maps HTTP status to §3.4 exit codes.
func httpStatusToExitCode(status int) int {
	switch {
	case status == http.StatusOK || status == http.StatusCreated ||
		status == http.StatusAccepted || status == http.StatusNoContent:
		return exitOK
	case status == http.StatusNotFound:
		return exitNotFound
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return exitUnauth
	case status == http.StatusConflict:
		return exitConflict
	case status >= 500:
		return exitServerError
	default:
		return exitUsage
	}
}

// isLoopbackHost reports whether host is localhost or a loopback IP.
// Copied from cmd/git-tainted (must not share across cmd/).
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// checkServerURL validates the server URL: https always OK; http only for
// loopback unless insecure.
func checkServerURL(raw string, insecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid server URL %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if insecure || isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("refusing plaintext server %q over the network — use https:// or pass --insecure", raw)
	default:
		return fmt.Errorf("server URL %q must be http or https", raw)
	}
}

// envValue returns the value of the named env var from an environ slice.
func envValue(environ []string, key string) string {
	prefix := key + "="
	for _, e := range environ {
		if strings.HasPrefix(e, prefix) {
			return e[len(prefix):]
		}
	}
	return ""
}

// envBool reports whether an env key is set to a truthy value (1/true/yes/on).
func envBool(environ []string, key string) bool {
	switch strings.ToLower(strings.TrimSpace(envValue(environ, key))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// ---- Wire types (thin, no oapi import) ----

// wireRemote mirrors the Remote JSON schema.
type wireRemote struct {
	ID                  int64   `json:"id"`
	URL                 string  `json:"url"`
	NormalizedURL       string  `json:"normalized_url"`
	Transport           string  `json:"transport"`
	SyncIntervalNS      int64   `json:"sync_interval_ns"`
	StalenessBudgetNS   int64   `json:"staleness_budget_ns"`
	TaintAnyTagDeletion bool    `json:"taint_any_tag_deletion"`
	HashAlgo            *string `json:"hash_algo,omitempty"`
	Status              string  `json:"status"`
	LastOKNS            int64   `json:"last_ok_ns"`
	LastErr             string  `json:"last_err"`
	ConsecutiveFailures int     `json:"consecutive_failures"`
	ChainLen            int64   `json:"chain_len"`
	RemovedAtNS         *int64  `json:"removed_at_ns,omitempty"`
	CreatedAtNS         int64   `json:"created_at_ns"`
	UpdatedAtNS         int64   `json:"updated_at_ns"`
}

// wireRemoteList mirrors the RemoteList JSON schema.
type wireRemoteList struct {
	Items      []wireRemote `json:"items"`
	NextCursor *int64       `json:"next_cursor,omitempty"`
}

// wireTag mirrors the Tag JSON schema.
type wireTag struct {
	ID               int64   `json:"id"`
	RemoteID         int64   `json:"remote_id"`
	TagName          string  `json:"tag_name"`
	CurrentOID       *string `json:"current_oid,omitempty"`
	CurrentPeeledOID *string `json:"current_peeled_oid,omitempty"`
	IsAnnotated      bool    `json:"is_annotated"`
	FirstOID         *string `json:"first_oid,omitempty"`
	FirstSeenNS      int64   `json:"first_seen_ns"`
	LastSeenNS       int64   `json:"last_seen_ns"`
	LastChangedNS    int64   `json:"last_changed_ns"`
	Deleted          bool    `json:"deleted"`
	Tainted          bool    `json:"tainted"`
	TaintFirstNS     *int64  `json:"taint_first_ns,omitempty"`
	ObservationCount int64   `json:"observation_count"`
}

// wireTagList mirrors the TagList JSON schema.
type wireTagList struct {
	Items      []wireTag `json:"items"`
	NextCursor *int64    `json:"next_cursor,omitempty"`
}

// wireTaintEvent mirrors the TaintEvent JSON schema.
type wireTaintEvent struct {
	ID            int64   `json:"id"`
	RemoteID      int64   `json:"remote_id"`
	RefID         int64   `json:"ref_id"`
	Reason        string  `json:"reason"`
	ObservationID *int64  `json:"observation_id,omitempty"`
	FromOID       *string `json:"from_oid,omitempty"`
	ToOID         *string `json:"to_oid,omitempty"`
	DetectedAtNS  int64   `json:"detected_at_ns"`
	AckedAtNS     *int64  `json:"acked_at_ns,omitempty"`
	AckedBy       *string `json:"acked_by,omitempty"`
	AckNote       *string `json:"ack_note,omitempty"`
	Detail        string  `json:"detail"`
}

// wireTaintEventList mirrors the TaintEventList JSON schema.
type wireTaintEventList struct {
	Items      []wireTaintEvent `json:"items"`
	NextCursor *int64           `json:"next_cursor,omitempty"`
}

// wireSyncEntry mirrors the SyncEntry JSON schema.
type wireSyncEntry struct {
	ID               int64   `json:"id"`
	RemoteID         int64   `json:"remote_id"`
	Trigger          string  `json:"trigger"`
	StartedNS        int64   `json:"started_ns"`
	FinishedNS       int64   `json:"finished_ns"`
	Status           string  `json:"status"`
	TagsSeen         int     `json:"tags_seen"`
	TagsChanged      int     `json:"tags_changed"`
	Error            string  `json:"error,omitempty"`
	ChainHeadBefore  *string `json:"chain_head_before,omitempty"`
	ChainHeadAfter   *string `json:"chain_head_after,omitempty"`
}

// wireSyncAuditList mirrors the SyncAuditList JSON schema.
type wireSyncAuditList struct {
	Items      []wireSyncEntry `json:"items"`
	NextCursor *int64          `json:"next_cursor,omitempty"`
}

// wireCreateRemoteReq mirrors CreateRemoteRequest.
type wireCreateRemoteReq struct {
	URL                 string `json:"url"`
	Transport           string `json:"transport"`
	SyncIntervalNS      *int64 `json:"sync_interval_ns,omitempty"`
	TaintAnyTagDeletion *bool  `json:"taint_any_tag_deletion,omitempty"`
}

// wireUpdateRemoteReq mirrors UpdateRemoteRequest (omitempty for patch semantics).
type wireUpdateRemoteReq struct {
	SyncIntervalNS    *int64  `json:"sync_interval_ns,omitempty"`
	StalenessBudgetNS *int64  `json:"staleness_budget_ns,omitempty"`
	Status            *string `json:"status,omitempty"`
}

// wireAckReq mirrors AckRequest.
type wireAckReq struct {
	AckedBy string `json:"acked_by"`
	AckNote string `json:"ack_note,omitempty"`
}
