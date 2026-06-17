package seed

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// peerClient is a thin HTTP client over a single peer git-tainted server's open
// read endpoints (listRemotes / listTags / listTaintEvents). It deserializes into
// the local DTOs below, which mirror the Remote / Tag / TaintEvent wire shapes
// (spec/openapi.yaml) — it does NOT import internal/api/oapi, the same lean
// pattern as the CLIs (cmd/git-tainted). Pagination + the transport guard +
// per-request deadline are applied by the Seeder via the shared http.Client.
type peerClient struct {
	http    *http.Client
	baseURL string // peer base URL, trailing slash trimmed
}

// wireRemote mirrors the openapi Remote schema (only the fields the seed needs).
type wireRemote struct {
	ID                  int64  `json:"id"`
	URL                 string `json:"url"`
	NormalizedURL       string `json:"normalized_url"`
	Transport           string `json:"transport"`
	TaintAnyTagDeletion bool   `json:"taint_any_tag_deletion"`
}

// wireRemoteList mirrors RemoteList.
type wireRemoteList struct {
	Items      []wireRemote `json:"items"`
	NextCursor *int64       `json:"next_cursor"`
}

// wireTag mirrors the openapi Tag schema. Oids are hex strings (nullable). The
// is_annotated / current_peeled_oid fields are load-bearing for C1 (annotated-tag
// peeled fidelity).
type wireTag struct {
	ID               int64   `json:"id"`
	RemoteID         int64   `json:"remote_id"`
	TagName          string  `json:"tag_name"`
	CurrentOID       *string `json:"current_oid"`
	CurrentPeeledOID *string `json:"current_peeled_oid"`
	IsAnnotated      *bool   `json:"is_annotated"`
	FirstOID         *string `json:"first_oid"`
	FirstSeenNS      int64   `json:"first_seen_ns"`
	LastSeenNS       int64   `json:"last_seen_ns"`
	Deleted          bool    `json:"deleted"`
	Tainted          bool    `json:"tainted"`
	TaintFirstNS     *int64  `json:"taint_first_ns"`
}

// wireTagList mirrors TagList.
type wireTagList struct {
	Items      []wireTag `json:"items"`
	NextCursor *int64    `json:"next_cursor"`
}

// wireTaintEvent mirrors the openapi TaintEvent schema. from_oid empty ⇒ a
// recreation genesis; to_oid empty ⇒ a deletion.
type wireTaintEvent struct {
	ID           int64   `json:"id"`
	RemoteID     int64   `json:"remote_id"`
	RefID        int64   `json:"ref_id"`
	Reason       string  `json:"reason"`
	FromOID      *string `json:"from_oid"`
	ToOID        *string `json:"to_oid"`
	DetectedAtNS int64   `json:"detected_at_ns"`
}

// wireTaintEventList mirrors TaintEventList.
type wireTaintEventList struct {
	Items      []wireTaintEvent `json:"items"`
	NextCursor *int64           `json:"next_cursor"`
}

// newPeerClient validates the peer base URL against the transport guard and
// returns a client. insecure permits plaintext http:// to non-loopback hosts.
func newPeerClient(httpClient *http.Client, baseURL string, insecure bool) (*peerClient, error) {
	if err := checkPeerURL(baseURL, insecure); err != nil {
		return nil, err
	}
	return &peerClient{http: httpClient, baseURL: strings.TrimRight(baseURL, "/")}, nil
}

// getJSON issues GET path?query and decodes the JSON body into out. A non-200
// status is an error (its votes will be dropped). The caller supplies the
// request context (carrying the per-request deadline + the concurrency slot).
func (c *peerClient) getJSON(ctx context.Context, path string, query url.Values, out any) error {
	reqURL := c.baseURL + path
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("build request %s: %w", path, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: peer returned HTTP %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// listRemotes paginates GET /v1/remotes, returning every remote the peer reports.
// maxPages bounds the loop (a malformed peer cannot drive it unbounded). Stops on
// empty items OR next_cursor==0 (the pinned pagination contract, spec §4.3).
func (c *peerClient) listRemotes(ctx context.Context, maxPages int) ([]wireRemote, error) {
	var all []wireRemote
	cursor := int64(0)
	for page := 0; page < maxPages; page++ {
		q := url.Values{}
		q.Set("limit", "1000")
		q.Set("cursor", strconv.FormatInt(cursor, 10))
		var list wireRemoteList
		if err := c.getJSON(ctx, "/v1/remotes", q, &list); err != nil {
			return nil, err
		}
		if len(list.Items) == 0 {
			break
		}
		all = append(all, list.Items...)
		next := derefCursor(list.NextCursor)
		if next == 0 || next <= cursor {
			break
		}
		cursor = next
	}
	return all, nil
}

// listTags paginates GET /v1/remotes/{id}/tags for one peer-remote.
func (c *peerClient) listTags(ctx context.Context, remoteID int64, maxPages int) ([]wireTag, error) {
	var all []wireTag
	cursor := int64(0)
	for page := 0; page < maxPages; page++ {
		q := url.Values{}
		q.Set("limit", "1000")
		q.Set("cursor", strconv.FormatInt(cursor, 10))
		var list wireTagList
		if err := c.getJSON(ctx, fmt.Sprintf("/v1/remotes/%d/tags", remoteID), q, &list); err != nil {
			return nil, err
		}
		if len(list.Items) == 0 {
			break
		}
		all = append(all, list.Items...)
		next := derefCursor(list.NextCursor)
		if next == 0 || next <= cursor {
			break
		}
		cursor = next
	}
	return all, nil
}

// listTaintEvents paginates GET /v1/remotes/{id}/taint-events for one peer-remote.
func (c *peerClient) listTaintEvents(ctx context.Context, remoteID int64, maxPages int) ([]wireTaintEvent, error) {
	var all []wireTaintEvent
	cursor := int64(0)
	for page := 0; page < maxPages; page++ {
		q := url.Values{}
		q.Set("limit", "1000")
		q.Set("cursor", strconv.FormatInt(cursor, 10))
		var list wireTaintEventList
		if err := c.getJSON(ctx, fmt.Sprintf("/v1/remotes/%d/taint-events", remoteID), q, &list); err != nil {
			return nil, err
		}
		if len(list.Items) == 0 {
			break
		}
		all = append(all, list.Items...)
		next := derefCursor(list.NextCursor)
		if next == 0 || next <= cursor {
			break
		}
		cursor = next
	}
	return all, nil
}

// derefCursor returns 0 for a nil cursor pointer, else its value.
func derefCursor(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// checkPeerURL validates a peer base URL. Mirrors the CLI's checkServerURL
// (cmd/git-tainted): https is always allowed; plaintext http is refused for
// non-loopback hosts unless insecure is set.
func checkPeerURL(raw string, insecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid seed peer URL %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if insecure || isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("refusing plaintext seed peer %q over the network — use https:// or set GT_SEED_INSECURE", raw)
	default:
		return fmt.Errorf("seed peer URL %q must be http or https", raw)
	}
}

// isLoopbackHost reports whether host is localhost or a loopback IP literal.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
