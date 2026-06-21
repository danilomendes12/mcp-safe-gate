// verifier.go — verificação de bearer token do estágio 1 (E4), no caminho HTTP.
// (A doc do pacote está em auth.go.)
//
// NewVerifier constrói o sdkauth.TokenVerifier que o middleware
// RequireBearerToken do SDK usa para autenticar o cliente. Dois modos,
// config-driven:
//
//   - apikey: a API key estática é mapeada a um principal (mapa no mcpgate.yaml).
//   - jwt:    JWT HS256 assinado com segredo compartilhado; a identidade vem da
//     claim de principal (default "sub").
//
// Divisão de trabalho com o middleware do SDK: o verificador só AUTENTICA
// (assinatura, key conhecida, iss/aud) e EXTRAI as claims (principal, scopes,
// expiração) para o TokenInfo. Quem checa expiração e scopes exigidos é o
// próprio middleware (RequireBearerToken) — não duplicamos aqui. Por isso o
// verificador apenas preenche TokenInfo.Expiration/Scopes; a recusa por exp
// vencida ou scope insuficiente acontece no SDK.
//
// OAuth completo (oauthex, fluxo client-side) e JWT por JWKS/RS256 ficam para
// fase posterior, como o E4 prevê.

package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/danilomendes/mcpgate/internal/config"
)

// apiKeyNoExpiry é a expiração atribuída a uma API key estática. O middleware do
// SDK rejeita TokenInfo com Expiration zerada ("token missing expiration"), e
// API keys não expiram por si — então usamos uma data bem no futuro para
// satisfazer essa checagem sem inventar um vencimento real.
var apiKeyNoExpiry = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)

// defaultPrincipalClaim é a claim usada como principal quando não configurada.
const defaultPrincipalClaim = "sub"

// NewVerifier devolve o TokenVerifier e as opções do RequireBearerToken para o
// modo de auth configurado. Para mode none (ou vazio) devolve (nil, nil, nil):
// o caller não deve envolver o handler com auth — o caminho HTTP segue anônimo.
func NewVerifier(cfg config.Auth) (sdkauth.TokenVerifier, *sdkauth.RequireBearerTokenOptions, error) {
	opts := &sdkauth.RequireBearerTokenOptions{
		ResourceMetadataURL: cfg.ResourceMetadataURL,
		Scopes:              cfg.RequiredScopes,
	}
	switch cfg.Mode {
	case "", config.AuthNone:
		return nil, nil, nil
	case config.AuthAPIKey:
		return apiKeyVerifier(cfg.APIKeys), opts, nil
	case config.AuthJWT:
		return jwtVerifier(cfg.JWT), opts, nil
	case config.AuthOIDC:
		return oidcVerifier(cfg.OIDC), opts, nil
	default:
		return nil, nil, fmt.Errorf("auth.mode %q não suportado", cfg.Mode)
	}
}

// PrincipalFromTokenInfo extrai o principal do TokenInfo resolvido pelo
// middleware. Ausente/vazio => Anonymous (o pipeline nunca opera sem principal).
func PrincipalFromTokenInfo(ti *sdkauth.TokenInfo) string {
	if ti != nil && ti.UserID != "" {
		return ti.UserID
	}
	return Anonymous
}

// apiKeyVerifier resolve o principal a partir de uma API key estática.
func apiKeyVerifier(keys []config.APIKey) sdkauth.TokenVerifier {
	index := make(map[string]config.APIKey, len(keys))
	for _, k := range keys {
		index[k.Key] = k
	}
	return func(_ context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
		k, ok := index[token]
		if !ok {
			// %w para sdkauth.ErrInvalidToken => o middleware responde 401.
			return nil, fmt.Errorf("api key desconhecida: %w", sdkauth.ErrInvalidToken)
		}
		return &sdkauth.TokenInfo{
			UserID:     k.Principal,
			Scopes:     k.Scopes,
			Expiration: apiKeyNoExpiry,
		}, nil
	}
}

// jwtVerifier valida um JWT HS256 e extrai principal, scopes e expiração.
func jwtVerifier(cfg config.JWT) sdkauth.TokenVerifier {
	secret := []byte(cfg.Secret)
	principalClaim := cfg.PrincipalClaim
	if principalClaim == "" {
		principalClaim = defaultPrincipalClaim
	}
	return func(_ context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
		claims, err := verifyHS256(token, secret)
		if err != nil {
			return nil, err
		}
		if cfg.Issuer != "" && stringClaim(claims, "iss") != cfg.Issuer {
			return nil, fmt.Errorf("issuer inválido: %w", sdkauth.ErrInvalidToken)
		}
		if cfg.Audience != "" && !audienceMatches(claims, cfg.Audience) {
			return nil, fmt.Errorf("audience inválida: %w", sdkauth.ErrInvalidToken)
		}
		principal := stringClaim(claims, principalClaim)
		if principal == "" {
			return nil, fmt.Errorf("claim de principal %q ausente: %w", principalClaim, sdkauth.ErrInvalidToken)
		}
		return &sdkauth.TokenInfo{
			UserID:     principal,
			Scopes:     scopeClaim(claims),
			Expiration: expClaim(claims), // zerada se ausente => middleware rejeita
		}, nil
	}
}

// verifyHS256 valida a assinatura HS256 de um JWT compacto e devolve as claims.
// Não checa expiração (responsabilidade do middleware do SDK).
func verifyHS256(token string, secret []byte) (map[string]any, error) {
	parts := splitJWT(token)
	if parts == nil {
		return nil, fmt.Errorf("jwt malformado: %w", sdkauth.ErrInvalidToken)
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := decodeJSONSegment(parts[0], &header); err != nil {
		return nil, fmt.Errorf("header jwt: %w", sdkauth.ErrInvalidToken)
	}
	if header.Alg != "HS256" {
		// Recusa explícita de "alg":"none" e de algoritmos não suportados.
		return nil, fmt.Errorf("alg %q não suportado (use HS256): %w", header.Alg, sdkauth.ErrInvalidToken)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := mac.Sum(nil)
	got, err := decodeSegment(parts[2])
	if err != nil {
		return nil, fmt.Errorf("assinatura jwt: %w", sdkauth.ErrInvalidToken)
	}
	if !hmac.Equal(got, want) {
		return nil, fmt.Errorf("assinatura jwt inválida: %w", sdkauth.ErrInvalidToken)
	}

	var claims map[string]any
	if err := decodeJSONSegment(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("payload jwt: %w", sdkauth.ErrInvalidToken)
	}
	return claims, nil
}

// splitJWT divide um JWT compacto em [header, payload, signature]. Devolve nil se
// não houver exatamente três segmentos.
func splitJWT(token string) []string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	return parts
}

// decodeSegment decodifica um segmento base64url (sem padding) de um JWT.
func decodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}

// decodeJSONSegment decodifica um segmento base64url e desserializa o JSON em out.
func decodeJSONSegment(seg string, out any) error {
	raw, err := decodeSegment(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// stringClaim devolve a claim como string, ou "" se ausente/não-string.
func stringClaim(claims map[string]any, key string) string {
	s, _ := claims[key].(string)
	return s
}

// expClaim extrai a claim `exp` (segundos epoch) como time.Time. Ausente => zero.
func expClaim(claims map[string]any) time.Time {
	if exp, ok := claims["exp"].(float64); ok {
		return time.Unix(int64(exp), 0)
	}
	return time.Time{}
}

// scopeClaim normaliza os scopes do token: aceita `scope` (string separada por
// espaço, padrão OAuth2) ou `scopes` (array de strings).
func scopeClaim(claims map[string]any) []string {
	if s, ok := claims["scope"].(string); ok && s != "" {
		return strings.Fields(s)
	}
	if arr, ok := claims["scopes"].([]any); ok {
		scopes := make([]string, 0, len(arr))
		for _, v := range arr {
			if s, ok := v.(string); ok {
				scopes = append(scopes, s)
			}
		}
		return scopes
	}
	return nil
}

// audienceMatches casa `aud` contra want; aceita string única ou array.
func audienceMatches(claims map[string]any, want string) bool {
	switch aud := claims["aud"].(type) {
	case string:
		return aud == want
	case []any:
		for _, v := range aud {
			if s, ok := v.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
