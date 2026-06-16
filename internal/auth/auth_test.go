package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/mivanov93/git-tainted/internal/config"
)

// ---- none ------------------------------------------------------------------

func TestNoneAuth(t *testing.T) {
	a := None()
	p, err := a.Authenticate(httptest.NewRequest(http.MethodPost, "/v1/remotes", nil))
	if err != nil {
		t.Fatalf("none must never error: %v", err)
	}
	if p != AnonymousPrincipal {
		t.Errorf("principal = %q, want %q", p, AnonymousPrincipal)
	}
	if a.Challenge() != "" {
		t.Errorf("none challenge = %q, want empty", a.Challenge())
	}
}

// ---- apikey ----------------------------------------------------------------

func apiKeyReqBearer(key string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/remotes", nil)
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	return r
}

func apiKeyReqHeader(key string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/remotes", nil)
	if key != "" {
		r.Header.Set("X-API-Key", key)
	}
	return r
}

func TestAPIKeyAuth(t *testing.T) {
	a, err := newAPIKeyAuth([]string{"secret123", "  ", "second-key"}, nil)
	if err != nil {
		t.Fatalf("newAPIKeyAuth: %v", err)
	}

	tests := []struct {
		name    string
		req     *http.Request
		wantErr error
	}{
		{"valid bearer", apiKeyReqBearer("secret123"), nil},
		{"valid bearer second key", apiKeyReqBearer("second-key"), nil},
		{"valid X-API-Key", apiKeyReqHeader("secret123"), nil},
		{"missing", apiKeyReqBearer(""), errMissingCredential},
		{"wrong key", apiKeyReqBearer("nope"), errBadCredential},
		{"empty X-API-Key", apiKeyReqHeader(""), errMissingCredential},
		{"wrong scheme (Basic)", basicReq("secret123", "x"), errMissingCredential},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := a.Authenticate(tc.req)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && p == "" {
				t.Fatalf("expected non-empty principal on success")
			}
		})
	}

	if a.Challenge() != "Bearer" {
		t.Errorf("apikey challenge = %q, want Bearer", a.Challenge())
	}
}

func TestAPIKeyAuth_SHA256DigestConfig(t *testing.T) {
	// Pre-hashed digest path: hash "secret123" with sha256 and configure the hex.
	const key = "secret123"
	// echo -n secret123 | sha256sum
	const digest = "fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4"
	a, err := newAPIKeyAuth(nil, []string{digest})
	if err != nil {
		t.Fatalf("newAPIKeyAuth(digest): %v", err)
	}
	if _, err := a.Authenticate(apiKeyReqBearer(key)); err != nil {
		t.Fatalf("digest-configured key rejected: %v", err)
	}
	if _, err := a.Authenticate(apiKeyReqBearer("wrong")); !errors.Is(err, errBadCredential) {
		t.Fatalf("wrong key under digest config: err = %v", err)
	}
}

func TestAPIKeyAuth_ConfigErrors(t *testing.T) {
	if _, err := newAPIKeyAuth(nil, nil); err == nil {
		t.Error("expected error for apikey with no keys")
	}
	if _, err := newAPIKeyAuth([]string{"  "}, nil); err == nil {
		t.Error("expected error for apikey with only blank keys")
	}
	if _, err := newAPIKeyAuth(nil, []string{"not-hex"}); err == nil {
		t.Error("expected error for malformed hex digest")
	}
	if _, err := newAPIKeyAuth(nil, []string{"abcd"}); err == nil {
		t.Error("expected error for wrong-length digest")
	}
}

// ---- basic -----------------------------------------------------------------

func basicReq(user, pass string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/remotes", nil)
	if user != "" || pass != "" {
		r.SetBasicAuth(user, pass)
	}
	return r
}

func bcryptHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	return string(h)
}

func TestBasicAuth(t *testing.T) {
	aliceHash := bcryptHash(t, "alice-pw")
	bobHash := bcryptHash(t, "bob-pw")
	a, err := newBasicAuth([]string{"alice:" + aliceHash, "bob:" + bobHash})
	if err != nil {
		t.Fatalf("newBasicAuth: %v", err)
	}

	tests := []struct {
		name    string
		req     *http.Request
		wantErr error
		wantP   string
	}{
		{"valid alice", basicReq("alice", "alice-pw"), nil, "basic:alice"},
		{"valid bob", basicReq("bob", "bob-pw"), nil, "basic:bob"},
		{"wrong password", basicReq("alice", "nope"), errBadCredential, ""},
		{"unknown user", basicReq("carol", "whatever"), errBadCredential, ""},
		{"no credentials", basicReq("", ""), errMissingCredential, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := a.Authenticate(tc.req)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if p != tc.wantP {
				t.Errorf("principal = %q, want %q", p, tc.wantP)
			}
		})
	}

	if a.Challenge() != `Basic realm="git-tainted"` {
		t.Errorf("basic challenge = %q", a.Challenge())
	}
}

func TestBasicAuth_ConfigErrors(t *testing.T) {
	if _, err := newBasicAuth(nil); err == nil {
		t.Error("expected error for basic with no users")
	}
	if _, err := newBasicAuth([]string{"no-colon-entry"}); err == nil {
		t.Error("expected error for entry without colon")
	}
	if _, err := newBasicAuth([]string{"alice:not-a-bcrypt-hash"}); err == nil {
		t.Error("expected error for non-bcrypt hash")
	}
	if _, err := newBasicAuth([]string{":" + bcryptHash(t, "x")}); err == nil {
		t.Error("expected error for empty username")
	}
}

// ---- FromConfig ------------------------------------------------------------

func TestFromConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("none default", func(t *testing.T) {
		a, err := FromConfig(ctx, &config.Config{AuthMode: ""})
		if err != nil {
			t.Fatalf("FromConfig none: %v", err)
		}
		if _, ok := a.(noneAuth); !ok {
			t.Errorf("want noneAuth, got %T", a)
		}
	})

	t.Run("apikey ok", func(t *testing.T) {
		a, err := FromConfig(ctx, &config.Config{AuthMode: config.AuthModeAPIKey, APIKeys: "k1,k2"})
		if err != nil {
			t.Fatalf("FromConfig apikey: %v", err)
		}
		if a.Challenge() != "Bearer" {
			t.Errorf("apikey challenge = %q", a.Challenge())
		}
	})

	t.Run("apikey no keys fatal", func(t *testing.T) {
		if _, err := FromConfig(ctx, &config.Config{AuthMode: config.AuthModeAPIKey}); err == nil {
			t.Error("expected fatal error for apikey with no keys")
		}
	})

	t.Run("basic ok", func(t *testing.T) {
		_, err := FromConfig(ctx, &config.Config{AuthMode: config.AuthModeBasic, BasicAuth: "alice:" + bcryptHash(t, "pw")})
		if err != nil {
			t.Fatalf("FromConfig basic: %v", err)
		}
	})

	t.Run("basic no users fatal", func(t *testing.T) {
		if _, err := FromConfig(ctx, &config.Config{AuthMode: config.AuthModeBasic}); err == nil {
			t.Error("expected fatal error for basic with no users")
		}
	})

	t.Run("jwks missing url fatal", func(t *testing.T) {
		if _, err := FromConfig(ctx, &config.Config{AuthMode: config.AuthModeJWKS, JWTIssuer: "i", JWTAudience: "a"}); err == nil {
			t.Error("expected fatal error for jwks with no URL")
		}
	})

	t.Run("jwks missing issuer fatal", func(t *testing.T) {
		if _, err := FromConfig(ctx, &config.Config{AuthMode: config.AuthModeJWKS, JWKSURL: "https://x/jwks", JWTAudience: "a"}); err == nil {
			t.Error("expected fatal error for jwks with no issuer")
		}
	})

	t.Run("jwks missing audience fatal", func(t *testing.T) {
		if _, err := FromConfig(ctx, &config.Config{AuthMode: config.AuthModeJWKS, JWKSURL: "https://x/jwks", JWTIssuer: "i"}); err == nil {
			t.Error("expected fatal error for jwks with no audience")
		}
	})

	t.Run("jwks bad alg fatal", func(t *testing.T) {
		cfg := &config.Config{AuthMode: config.AuthModeJWKS, JWKSURL: "https://x/jwks", JWTIssuer: "i", JWTAudience: "a", JWTAlgs: "HS256"}
		if _, err := FromConfig(ctx, cfg); err == nil {
			t.Error("expected fatal error for jwks with HS256 in allowlist")
		}
	})

	t.Run("jwks ok (no network at construction)", func(t *testing.T) {
		cfg := &config.Config{AuthMode: config.AuthModeJWKS, JWKSURL: "https://idp.test/jwks.json", JWTIssuer: "i", JWTAudience: "a"}
		a, err := FromConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("FromConfig jwks: %v", err)
		}
		if a.Challenge() != "Bearer" {
			t.Errorf("jwks challenge = %q", a.Challenge())
		}
	})
}
