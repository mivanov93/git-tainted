package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// signHS256 mints a token signed with a symmetric HS256 key carrying the given
// kid. A jwks-mode server must reject it regardless of whether a key with that
// kid exists in the JWKS, because HS* is categorically disallowed and WithKeySet
// never uses a symmetric key for an asymmetric verification.
func signHS256(t *testing.T, kid string) string {
	t.Helper()
	secret := []byte("super-secret-hmac-key-0123456789")
	key, err := jwk.Import[jwk.Key](secret)
	if err != nil {
		t.Fatalf("import hs key: %v", err)
	}
	_ = key.Set(jwk.KeyIDKey, kid)
	_ = key.Set(jwk.AlgorithmKey, jwa.HS256())

	tok, err := jwt.NewBuilder().
		Issuer(testIssuer).
		Audience([]string{testAud}).
		Subject("attacker").
		Expiration(time.Now().Add(5 * time.Minute)).
		IssuedAt(time.Now()).
		Build()
	if err != nil {
		t.Fatalf("build hs token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
	if err != nil {
		t.Fatalf("sign hs token: %v", err)
	}
	return string(signed)
}

// noneToken hand-builds an unsigned ("alg":"none") compact JWT. jwx will not sign
// one for us, so we assemble header.payload. with an empty signature segment —
// exactly the shape of the classic alg-confusion attack. It must be rejected.
func noneToken(t *testing.T) string {
	t.Helper()
	b64 := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := map[string]string{"alg": "none", "typ": "JWT", "kid": "key-1"}
	payload := map[string]any{
		"iss": testIssuer,
		"aud": testAud,
		"sub": "attacker",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	return b64(header) + "." + b64(payload) + "."
}
