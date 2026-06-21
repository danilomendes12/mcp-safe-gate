package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/danilomendes/mcpgate/internal/config"
)

// rsaKey é uma chave RSA de teste com seu kid.
type rsaKey struct {
	kid  string
	priv *rsa.PrivateKey
}

func newRSAKey(t *testing.T, kid string) rsaKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return rsaKey{kid: kid, priv: priv}
}

// jwk monta a representação JWK pública da chave.
func (k rsaKey) jwk() map[string]any {
	pub := k.priv.PublicKey
	eb := big.NewInt(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": k.kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(eb),
	}
}

// signRS256 monta e assina um JWT compacto. alg/kid configuráveis para os casos
// negativos; tamper corrompe a assinatura.
func signRS256(t *testing.T, k rsaKey, alg, kid string, claims map[string]any, tamper bool) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]any{"alg": alg, "kid": kid, "typ": "JWT"})
	payload := enc(claims)
	signingInput := header + "." + payload
	if alg == "none" {
		return signingInput + "."
	}
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if tamper {
		sig[0] ^= 0xff
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksServer serve um JWKS mutável (para o teste de rotação).
type jwksServer struct {
	mu   sync.Mutex
	keys []rsaKey
	srv  *httptest.Server
}

func newJWKSServer(t *testing.T, keys ...rsaKey) *jwksServer {
	js := &jwksServer{keys: keys}
	js.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		js.mu.Lock()
		defer js.mu.Unlock()
		set := make([]map[string]any, 0, len(js.keys))
		for _, k := range js.keys {
			set = append(set, k.jwk())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": set})
	}))
	t.Cleanup(js.srv.Close)
	return js
}

func (js *jwksServer) rotate(keys ...rsaKey) {
	js.mu.Lock()
	defer js.mu.Unlock()
	js.keys = keys
}

func validClaims() map[string]any {
	return map[string]any{
		"sub":   "alice",
		"scope": "tools:call read",
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
		"iss":   "https://idp.test",
		"aud":   "mcpgate",
	}
}

func TestOIDCVerifierValid(t *testing.T) {
	key := newRSAKey(t, "k1")
	js := newJWKSServer(t, key)

	v := oidcVerifier(config.OIDC{
		JWKSURI:  js.srv.URL,
		Issuer:   "https://idp.test",
		Audience: "mcpgate",
	})

	tok := signRS256(t, key, "RS256", "k1", validClaims(), false)
	ti, err := v(context.Background(), tok, nil)
	if err != nil {
		t.Fatalf("token válido: %v", err)
	}
	if ti.UserID != "alice" {
		t.Errorf("UserID = %q, quer alice", ti.UserID)
	}
	if len(ti.Scopes) != 2 {
		t.Errorf("Scopes = %v, quer [tools:call read]", ti.Scopes)
	}
	if !ti.Expiration.After(time.Now()) {
		t.Errorf("Expiration = %v, quer no futuro", ti.Expiration)
	}
}

func TestOIDCVerifierRejections(t *testing.T) {
	key := newRSAKey(t, "k1")
	other := newRSAKey(t, "k1") // mesmo kid, chave diferente
	js := newJWKSServer(t, key)
	v := oidcVerifier(config.OIDC{JWKSURI: js.srv.URL, Issuer: "https://idp.test", Audience: "mcpgate"})

	cases := []struct {
		name string
		tok  string
	}{
		{"kid desconhecido", signRS256(t, key, "RS256", "desconhecido", validClaims(), false)},
		{"assinatura inválida", signRS256(t, key, "RS256", "k1", validClaims(), true)},
		{"assinada por outra chave", signRS256(t, other, "RS256", "k1", validClaims(), false)},
		{"alg none", signRS256(t, key, "none", "k1", validClaims(), false)},
		{"issuer errado", signRS256(t, key, "RS256", "k1", withClaim(validClaims(), "iss", "https://evil.test"), false)},
		{"audience errada", signRS256(t, key, "RS256", "k1", withClaim(validClaims(), "aud", "outro"), false)},
		{"principal ausente", signRS256(t, key, "RS256", "k1", withoutClaim(validClaims(), "sub"), false)},
		{"malformado", "nao.e.jwt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v(context.Background(), tc.tok, nil); !errors.Is(err, sdkauth.ErrInvalidToken) {
				t.Errorf("erro = %v, quer ErrInvalidToken", err)
			}
		})
	}
}

func TestOIDCDiscovery(t *testing.T) {
	key := newRSAKey(t, "k1")
	js := newJWKSServer(t, key)

	// IdP que expõe o openid-configuration apontando para o JWKS.
	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   idp.URL,
				"jwks_uri": js.srv.URL,
			})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(idp.Close)

	// Só o issuer configurado: o jwks_uri é descoberto.
	v := oidcVerifier(config.OIDC{Issuer: idp.URL})
	claims := withClaim(validClaims(), "iss", idp.URL)
	tok := signRS256(t, key, "RS256", "k1", claims, false)
	if _, err := v(context.Background(), tok, nil); err != nil {
		t.Fatalf("discovery: %v", err)
	}
}

func TestJWKSRotation(t *testing.T) {
	k1 := newRSAKey(t, "k1")
	k2 := newRSAKey(t, "k2")
	js := newJWKSServer(t, k1)

	cache := newJWKSCache(js.srv.URL, "")
	cache.coolDown = 0 // permite refetch imediato no kid desconhecido

	// k1 resolve.
	if _, err := cache.key(context.Background(), "k1"); err != nil {
		t.Fatalf("k1: %v", err)
	}
	// IdP rotaciona para k2; o cache deve refazer o fetch ao ver o kid novo.
	js.rotate(k2)
	if _, err := cache.key(context.Background(), "k2"); err != nil {
		t.Fatalf("k2 pós-rotação: %v", err)
	}
}

// withClaim devolve uma cópia de claims com key=val.
func withClaim(claims map[string]any, key string, val any) map[string]any {
	out := map[string]any{}
	for k, v := range claims {
		out[k] = v
	}
	out[key] = val
	return out
}

func withoutClaim(claims map[string]any, key string) map[string]any {
	out := withClaim(claims, key, nil)
	delete(out, key)
	return out
}
