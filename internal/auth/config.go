package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/mivanov93/git-tainted/internal/config"
)

// FromConfig selects and validates the Authenticator for the configured
// GT_AUTH_MODE. Misconfiguration (apikey with no keys, basic with no users or a
// bad hash, jwks missing url/issuer/audience or with a bad algorithm allowlist)
// is returned as an error so main can treat it as fatal at startup — never a
// per-request failure (spec §2.7).
//
// The returned Authenticator's lifetime is tied to ctx for the jwks mode (its
// background JWKS-refresh goroutine stops when ctx is cancelled); the other modes
// ignore ctx.
func FromConfig(ctx context.Context, cfg *config.Config) (Authenticator, error) {
	switch modeOf(cfg) {
	case config.AuthModeNone:
		return None(), nil

	case config.AuthModeAPIKey:
		return newAPIKeyAuth(splitList(cfg.APIKeys), splitList(cfg.APIKeysSHA256))

	case config.AuthModeBasic:
		return newBasicAuth(splitList(cfg.BasicAuth))

	case config.AuthModeJWKS:
		if strings.TrimSpace(cfg.JWKSURL) == "" {
			return nil, fmt.Errorf("auth: jwks mode requires GT_JWKS_URL")
		}
		if strings.TrimSpace(cfg.JWTIssuer) == "" {
			return nil, fmt.Errorf("auth: jwks mode requires GT_JWT_ISSUER")
		}
		if strings.TrimSpace(cfg.JWTAudience) == "" {
			return nil, fmt.Errorf("auth: jwks mode requires GT_JWT_AUDIENCE")
		}
		algs, err := parseAlgs(cfg.JWTAlgs)
		if err != nil {
			return nil, err
		}
		return newJWKSAuth(ctx, cfg.JWKSURL, cfg.JWTIssuer, cfg.JWTAudience, algs)

	default:
		// Defensive: config.Load already rejects unknown modes, so this is
		// unreachable in practice.
		return nil, fmt.Errorf("auth: unsupported GT_AUTH_MODE %q", cfg.AuthMode)
	}
}

// splitList splits a comma-separated configuration value into trimmed, non-empty
// entries.
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
