// Package git implements the GitRunner seam and URL validation/normalization.
// Full §7 subprocess hardening is in runner.go. This file provides:
//   - ValidateURL: full §7 hardening with verbatim+normalized+transport returns
//   - NormalizeURL: backward-compat wrapper used by Phase-1 API handlers
package git

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/mivanov93/git-tainted/internal/model"
)

const maxURLLen = 2048

// ValidateURL enforces the §7 URL rules and returns the verbatim original url,
// a canonicalized normalized_url (used for the remote-unique constraint), and
// the transport. Every rejection wraps model.ErrBadURL.
//
// Accepted: https://… and ssh — either ssh://… or the scp-like
// git@host:owner/repo form. Rejected: file/git/ext/fd/other transports,
// http (plaintext), option-injection (leading '-' anywhere structurally
// significant), control chars, over-length, and host-less forms.
func ValidateURL(raw string) (string, string, model.Transport, error) {
	if raw == "" {
		return "", "", "", fmt.Errorf("%w: empty url", model.ErrBadURL)
	}
	if len(raw) > maxURLLen {
		return "", "", "", fmt.Errorf("%w: url exceeds %d bytes", model.ErrBadURL, maxURLLen)
	}
	if i := strings.IndexFunc(raw, isControl); i >= 0 {
		return "", "", "", fmt.Errorf("%w: control char at %d", model.ErrBadURL, i)
	}
	if strings.HasPrefix(raw, "-") {
		return "", "", "", fmt.Errorf("%w: leading '-' (option injection)", model.ErrBadURL)
	}
	// Reject dangerous remote-helper transports explicitly (ext::, fd::, etc.).
	if strings.Contains(raw, "::") {
		return "", "", "", fmt.Errorf("%w: remote-helper transport ('::') refused", model.ErrBadURL)
	}

	switch {
	case strings.HasPrefix(raw, "https://"):
		norm, err := normalizeHTTPS(raw)
		if err != nil {
			return "", "", "", err
		}
		return raw, norm, model.TransportHTTPS, nil
	case strings.HasPrefix(raw, "ssh://"):
		norm, err := normalizeSSHScheme(raw)
		if err != nil {
			return "", "", "", err
		}
		return raw, norm, model.TransportSSH, nil
	case isSCPLike(raw):
		norm, err := normalizeSCP(raw)
		if err != nil {
			return "", "", "", err
		}
		return raw, norm, model.TransportSSH, nil
	default:
		return "", "", "", fmt.Errorf("%w: unsupported scheme/form (only https:// and ssh allowed)", model.ErrBadURL)
	}
}

// NormalizeURL is the backward-compat entry used by Phase-1 API handlers.
// It returns (normalizedURL, error) without the verbatim/transport returns.
// Delegates to ValidateURL.
func NormalizeURL(rawURL string) (string, error) {
	_, norm, _, err := ValidateURL(rawURL)
	return norm, err
}

func isControl(r rune) bool { return r <= 0x20 || r == 0x7f }

// isSCPLike reports whether raw is the scp-like ssh form user@host:path,
// disambiguated from a scheme URL (no "://") and from a windows path.
func isSCPLike(raw string) bool {
	if strings.Contains(raw, "://") {
		return false
	}
	at := strings.IndexByte(raw, '@')
	colon := strings.IndexByte(raw, ':')
	// require user@host:path shape with host between '@' and ':'
	return at > 0 && colon > at+1
}

func normalizeHTTPS(raw string) (string, error) {
	return normalizeURLScheme(raw, "https", "443")
}

func normalizeSSHScheme(raw string) (string, error) {
	return normalizeURLScheme(raw, "ssh", "22")
}

func normalizeURLScheme(raw, scheme, defaultPort string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: parse: %w", model.ErrBadURL, err)
	}
	if u.Scheme != scheme {
		return "", fmt.Errorf("%w: scheme mismatch", model.ErrBadURL)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("%w: missing host", model.ErrBadURL)
	}
	if strings.HasPrefix(host, "-") {
		return "", fmt.Errorf("%w: host begins with '-'", model.ErrBadURL)
	}
	port := u.Port()
	if port == defaultPort {
		port = ""
	}
	userinfo := ""
	if u.User != nil {
		name := u.User.Username()
		if strings.HasPrefix(name, "-") {
			return "", fmt.Errorf("%w: userinfo begins with '-'", model.ErrBadURL)
		}
		userinfo = name + "@"
	}
	authority := strings.ToLower(host)
	if port != "" {
		authority += ":" + port
	}
	path := strings.TrimRight(u.Path, "/")
	return scheme + "://" + userinfo + authority + path, nil
}

func normalizeSCP(raw string) (string, error) {
	at := strings.IndexByte(raw, '@')
	user := raw[:at]
	if user == "" || strings.HasPrefix(user, "-") {
		return "", fmt.Errorf("%w: scp userinfo invalid", model.ErrBadURL)
	}
	rest := raw[at+1:] // host:path
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 {
		return "", fmt.Errorf("%w: scp form missing ':path'", model.ErrBadURL)
	}
	host := rest[:colon]
	path := rest[colon+1:]
	if host == "" || strings.HasPrefix(host, "-") {
		return "", fmt.Errorf("%w: scp host invalid", model.ErrBadURL)
	}
	if strings.HasPrefix(path, "-") {
		return "", fmt.Errorf("%w: scp path begins with '-'", model.ErrBadURL)
	}
	path = strings.TrimRight(path, "/")
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "ssh://" + user + "@" + strings.ToLower(host) + path, nil
}
