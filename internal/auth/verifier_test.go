package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/danilomendes/mcpgate/internal/config"
)

// makeJWT monta um JWT compacto assinado em HS256 (ou com alg/assinatura
// alterados para os casos negativos).
func makeJWT(t *testing.T, secret, alg string, claims map[string]any, tamper bool) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]any{"alg": alg, "typ": "JWT"})
	payload := enc(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if tamper {
		sig = base64.RawURLEncoding.EncodeToString([]byte("assinatura-errada"))
	}
	return header + "." + payload + "." + sig
}

func TestNewVerifierModes(t *testing.T) {
	if v, _, err := NewVerifier(config.Auth{Mode: config.AuthNone}); err != nil || v != nil {
		t.Fatalf("mode none deveria devolver (nil,_,nil), got v=%v err=%v", v, err)
	}
	if v, _, err := NewVerifier(config.Auth{}); err != nil || v != nil {
		t.Fatalf("mode vazio deveria devolver (nil,_,nil), got v=%v err=%v", v, err)
	}
	if _, _, err := NewVerifier(config.Auth{Mode: "xpto"}); err == nil {
		t.Fatal("mode inválido deveria devolver erro")
	}
	// As opções carregam os scopes exigidos para o middleware do SDK.
	_, opts, err := NewVerifier(config.Auth{Mode: config.AuthAPIKey, RequiredScopes: []string{"a"}, APIKeys: []config.APIKey{{Key: "k", Principal: "p"}}})
	if err != nil {
		t.Fatalf("apikey: %v", err)
	}
	if len(opts.Scopes) != 1 || opts.Scopes[0] != "a" {
		t.Fatalf("opts.Scopes = %v, quer [a]", opts.Scopes)
	}
}

func TestAPIKeyVerifier(t *testing.T) {
	v, _, err := NewVerifier(config.Auth{
		Mode:    config.AuthAPIKey,
		APIKeys: []config.APIKey{{Key: "secret-1", Principal: "ci-bot", Scopes: []string{"tools:call"}}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	ti, err := v(context.Background(), "secret-1", nil)
	if err != nil {
		t.Fatalf("key válida: %v", err)
	}
	if ti.UserID != "ci-bot" {
		t.Errorf("UserID = %q, quer ci-bot", ti.UserID)
	}
	if len(ti.Scopes) != 1 || ti.Scopes[0] != "tools:call" {
		t.Errorf("Scopes = %v, quer [tools:call]", ti.Scopes)
	}
	// Expiração precisa ser futura: o middleware do SDK rejeita exp zerada.
	if !ti.Expiration.After(time.Now()) {
		t.Errorf("Expiration = %v, quer no futuro", ti.Expiration)
	}

	if _, err := v(context.Background(), "desconhecida", nil); !errors.Is(err, sdkauth.ErrInvalidToken) {
		t.Errorf("key desconhecida: erro = %v, quer ErrInvalidToken", err)
	}
}

func TestJWTVerifier(t *testing.T) {
	const secret = "super-secreto"
	base := config.JWT{Secret: secret, PrincipalClaim: "sub"}

	v, _, err := NewVerifier(config.Auth{Mode: config.AuthJWT, JWT: base})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	exp := float64(time.Now().Add(time.Hour).Unix())

	t.Run("válido", func(t *testing.T) {
		tok := makeJWT(t, secret, "HS256", map[string]any{"sub": "alice", "scope": "read write", "exp": exp}, false)
		ti, err := v(context.Background(), tok, nil)
		if err != nil {
			t.Fatalf("token válido: %v", err)
		}
		if ti.UserID != "alice" {
			t.Errorf("UserID = %q, quer alice", ti.UserID)
		}
		if len(ti.Scopes) != 2 {
			t.Errorf("Scopes = %v, quer [read write]", ti.Scopes)
		}
		if ti.Expiration.Unix() != int64(exp) {
			t.Errorf("Expiration = %v, quer exp do token", ti.Expiration)
		}
	})

	t.Run("assinatura inválida", func(t *testing.T) {
		tok := makeJWT(t, secret, "HS256", map[string]any{"sub": "alice", "exp": exp}, true)
		if _, err := v(context.Background(), tok, nil); !errors.Is(err, sdkauth.ErrInvalidToken) {
			t.Errorf("erro = %v, quer ErrInvalidToken", err)
		}
	})

	t.Run("alg none rejeitado", func(t *testing.T) {
		tok := makeJWT(t, secret, "none", map[string]any{"sub": "alice", "exp": exp}, false)
		if _, err := v(context.Background(), tok, nil); !errors.Is(err, sdkauth.ErrInvalidToken) {
			t.Errorf("erro = %v, quer ErrInvalidToken", err)
		}
	})

	t.Run("principal ausente", func(t *testing.T) {
		tok := makeJWT(t, secret, "HS256", map[string]any{"exp": exp}, false)
		if _, err := v(context.Background(), tok, nil); !errors.Is(err, sdkauth.ErrInvalidToken) {
			t.Errorf("erro = %v, quer ErrInvalidToken", err)
		}
	})

	t.Run("malformado", func(t *testing.T) {
		if _, err := v(context.Background(), "nao.e.jwt.valido", nil); !errors.Is(err, sdkauth.ErrInvalidToken) {
			t.Errorf("erro = %v, quer ErrInvalidToken", err)
		}
	})

	t.Run("issuer e audience", func(t *testing.T) {
		vv, _, err := NewVerifier(config.Auth{Mode: config.AuthJWT, JWT: config.JWT{Secret: secret, Issuer: "iss-ok", Audience: "aud-ok"}})
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		ok := makeJWT(t, secret, "HS256", map[string]any{"sub": "a", "iss": "iss-ok", "aud": "aud-ok", "exp": exp}, false)
		if _, err := vv(context.Background(), ok, nil); err != nil {
			t.Errorf("iss/aud corretos: %v", err)
		}
		badIss := makeJWT(t, secret, "HS256", map[string]any{"sub": "a", "iss": "outro", "aud": "aud-ok", "exp": exp}, false)
		if _, err := vv(context.Background(), badIss, nil); !errors.Is(err, sdkauth.ErrInvalidToken) {
			t.Errorf("iss errado: erro = %v, quer ErrInvalidToken", err)
		}
	})
}
