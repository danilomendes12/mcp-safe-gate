// oidc.go — modo `oidc` do estágio 1 (E4, leg norte): valida JWT RS256 emitido
// por um IdP externo, com as chaves públicas vindas do JWKS (ver jwks.go).
//
// Divisão de trabalho com o middleware do SDK (igual ao HS256): aqui validamos
// assinatura (RS256, chave casada pelo `kid`), `iss` e `aud`, e EXTRAÍMOS as
// claims (principal, scopes, exp) para o TokenInfo. Quem recusa por exp vencida
// ou scope insuficiente é o RequireBearerToken do SDK — não duplicamos.
//
// SAFE-MCP: validar a assinatura contra o JWKS do issuer configurado fecha a
// porta a um Rogue Authorization Server (SAFE-T1306) — um token assinado por
// outra chave/IdP não passa; e a checagem de `aud` evita aceitar token emitido
// para outro resource server (relacionado a SAFE-T1308, token scope substitution).

package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"net/http"
	"slices"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/danilomendes/mcpgate/internal/config"
)

// oidcVerifier constrói o TokenVerifier do modo oidc. As chaves do JWKS são
// resolvidas preguiçosamente no primeiro token e cacheadas (ver jwksCache).
func oidcVerifier(cfg config.OIDC) sdkauth.TokenVerifier {
	cache := newJWKSCache(cfg.JWKSURI, cfg.Issuer)
	principalClaim := cfg.PrincipalClaim
	if principalClaim == "" {
		principalClaim = defaultPrincipalClaim
	}
	algs := cfg.Algorithms
	if len(algs) == 0 {
		algs = []string{"RS256"}
	}

	return func(ctx context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
		claims, err := verifyRS256(ctx, token, cache, algs)
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

// verifyRS256 valida a assinatura RS256 de um JWT compacto contra a chave do
// JWKS casada pelo `kid` do header e devolve as claims. Não checa expiração
// (responsabilidade do middleware do SDK).
func verifyRS256(ctx context.Context, token string, cache *jwksCache, allowedAlgs []string) (map[string]any, error) {
	parts := splitJWT(token)
	if parts == nil {
		return nil, fmt.Errorf("jwt malformado: %w", sdkauth.ErrInvalidToken)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := decodeJSONSegment(parts[0], &header); err != nil {
		return nil, fmt.Errorf("header jwt: %w", sdkauth.ErrInvalidToken)
	}
	// Recusa explícita de "alg":"none" e de algoritmos fora da allowlist.
	if !slices.Contains(allowedAlgs, header.Alg) {
		return nil, fmt.Errorf("alg %q não permitido: %w", header.Alg, sdkauth.ErrInvalidToken)
	}
	if header.Kid == "" {
		return nil, fmt.Errorf("header jwt sem kid: %w", sdkauth.ErrInvalidToken)
	}

	pub, err := cache.key(ctx, header.Kid)
	if err != nil {
		return nil, fmt.Errorf("resolvendo chave do jwt: %w: %w", err, sdkauth.ErrInvalidToken)
	}

	sig, err := decodeSegment(parts[2])
	if err != nil {
		return nil, fmt.Errorf("assinatura jwt: %w", sdkauth.ErrInvalidToken)
	}
	signed := []byte(parts[0] + "." + parts[1])
	digest := sha256.Sum256(signed)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("assinatura jwt inválida: %w", sdkauth.ErrInvalidToken)
	}

	var claims map[string]any
	if err := decodeJSONSegment(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("payload jwt: %w", sdkauth.ErrInvalidToken)
	}
	return claims, nil
}
