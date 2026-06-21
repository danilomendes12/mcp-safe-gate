// metadata.go — Protected Resource Metadata (RFC 9728) do leg norte (E4). Permite
// que clientes MCP (e o Inspector) DESCUBRAM, a partir de um 401 com
// WWW-Authenticate, qual é o authorization server deste resource server.
//
// O gateway é o "protected resource"; o IdP (issuer) é o authorization server. O
// endpoint /.well-known/oauth-protected-resource publica esse vínculo. O
// middleware RequireBearerToken já aponta o cliente para cá via ResourceMetadataURL.

package auth

import (
	"net/http"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/danilomendes/mcpgate/internal/config"
)

// ProtectedResourceMetadataPath é o caminho padrão (RFC 9728 §3) do metadata.
const ProtectedResourceMetadataPath = "/.well-known/oauth-protected-resource"

// BuildResourceMetadata monta o Protected Resource Metadata a partir da config de
// auth, ou devolve nil quando não há informação suficiente para publicá-lo
// (mode sem authorization server, ou sem `resource` configurado). O endpoint só é
// servido quando isto é não-nil.
//
// AuthorizationServers aponta para o issuer do IdP (mode=oidc) ou para o issuer
// do JWT (mode=jwt, quando configurado). Em apikey/none não há AS a anunciar.
func BuildResourceMetadata(cfg config.Auth) *oauthex.ProtectedResourceMetadata {
	if cfg.Resource == "" {
		return nil
	}
	var authServers []string
	switch cfg.Mode {
	case config.AuthOIDC:
		if cfg.OIDC.Issuer != "" {
			authServers = []string{cfg.OIDC.Issuer}
		}
	case config.AuthJWT:
		if cfg.JWT.Issuer != "" {
			authServers = []string{cfg.JWT.Issuer}
		}
	}
	if len(authServers) == 0 {
		return nil
	}
	return &oauthex.ProtectedResourceMetadata{
		Resource:               cfg.Resource,
		AuthorizationServers:   authServers,
		ScopesSupported:        cfg.RequiredScopes,
		BearerMethodsSupported: []string{"header"},
	}
}

// MetadataHandler devolve o http.Handler que serve o metadata (com CORS, RFC
// 9728), ou nil quando não há metadata a publicar.
func MetadataHandler(cfg config.Auth) http.Handler {
	meta := BuildResourceMetadata(cfg)
	if meta == nil {
		return nil
	}
	return sdkauth.ProtectedResourceMetadataHandler(meta)
}
