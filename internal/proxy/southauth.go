package proxy

// southauth.go — leg SUL com autorização DELEGADA por usuário (E4-sul). Mapeia o
// principal verificado no norte → a credencial daquele usuário no upstream, em
// vez de uma credencial compartilhada (confused deputy, SAFE-T1307) ou de
// repassar o bearer do norte ao upstream (token passthrough, proibido pela spec
// de auth do MCP; abre token scope substitution, SAFE-T1308).
//
// Dois pontos de extensão, um por concern:
//   - southAuthMiddleware: ADMISSÃO. Resolve a credencial e faz fail-closed (sem
//     credencial ⇒ nega, nunca cai na de outro usuário). Roda mesmo sem rede, o
//     que o torna testável com transports in-memory.
//   - perUserRoundTripper: INJEÇÃO. No leg HTTP, põe a credencial do usuário na
//     request ao upstream e SEMPRE remove qualquer Authorization herdado (garante
//     no-passthrough). A credencial viaja do middleware ao RoundTripper pelo
//     context da própria chamada (o SDK propaga o ctx do CallTool até o POST).

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/danilomendes/mcpgate/internal/auth"
	"github.com/danilomendes/mcpgate/internal/config"
	"github.com/danilomendes/mcpgate/internal/credstore"
)

// codeSouthAuthDenied é o código JSON-RPC do fail-closed do leg sul: a tool foi
// permitida ao principal (RBAC), mas não há credencial sul para ele naquele
// upstream — a chamada é negada sem nunca tocar o upstream.
const codeSouthAuthDenied = -32003

// newCredentialStore constrói o vault de credenciais sul a partir da config.
// Store vazio => nil (nenhum upstream per_user). A chave de cifra vem da env
// apontada por key_env, nunca do arquivo de config.
func newCredentialStore(cfg config.Credentials) (credstore.Store, error) {
	switch cfg.Store {
	case "":
		return nil, nil
	case config.CredStoreFile:
		keyB64 := os.Getenv(cfg.File.KeyEnv)
		if keyB64 == "" {
			return nil, fmt.Errorf("credentials: env %q (chave do vault) vazia", cfg.File.KeyEnv)
		}
		key, err := credstore.DecodeKey(keyB64)
		if err != nil {
			return nil, fmt.Errorf("credentials: %w", err)
		}
		return credstore.NewFileStore(cfg.File.Path, key)
	default:
		return nil, fmt.Errorf("credentials.store %q não suportado", cfg.Store)
	}
}

// southAuthByUpstream indexa a config de auth sul por nome de upstream.
func southAuthByUpstream(ups []config.Upstream) map[string]config.UpstreamAuth {
	m := make(map[string]config.UpstreamAuth, len(ups))
	for _, u := range ups {
		m[u.Name] = u.Auth
	}
	return m
}

// southAuthMiddleware resolve a credencial sul por usuário e aplica fail-closed
// para upstreams per_user. Só age em tools/call de upstream per_user; o resto
// passa direto (conta de serviço não depende do principal). A credencial
// resolvida segue no context até o RoundTripper; nada secreto é logado.
func (p *Proxy) southAuthMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if method != methodCallTool || p.credStore == nil {
			return next(ctx, method, req)
		}
		tool := callToolName(req)
		up := upstreamOf(tool)

		if sa, ok := p.southAuth[up]; !ok || sa.Type != config.SouthAuthPerUser {
			return next(ctx, method, req)
		}

		principal := auth.PrincipalFromContext(ctx)
		cred, err := p.credStore.Lookup(ctx, principal, up)
		if err != nil {
			// Fail-closed: sem credencial do PRÓPRIO principal, nega — nunca cai
			// numa credencial compartilhada nem na conta de serviço por engano.
			p.auditDeny(principal, tool, "no_south_credential")
			return nil, &jsonrpc.Error{
				Code:    codeSouthAuthDenied,
				Message: fmt.Sprintf("sem credencial de upstream para o principal %q em %q (delegated auth)", principal, up),
			}
		}
		ctx = credstore.WithCredential(ctx, cred)
		return next(ctx, method, req)
	}
}

// southHTTPClient devolve o *http.Client do leg sul de um upstream HTTP conforme
// o tipo de auth, ou (nil, nil) quando não há auth sul (o transporte usa o
// default). É o ponto único onde a credencial do gateway/usuário é injetada.
func (p *Proxy) southHTTPClient(up config.Upstream) (*http.Client, error) {
	typ := up.Auth.Type
	if typ == "" {
		// Compat: bearer_token inline sem bloco auth => service_bearer.
		if up.BearerToken == "" {
			return nil, nil
		}
		typ = config.SouthAuthServiceBearer
	}

	switch typ {
	case config.SouthAuthServiceBearer:
		token := up.BearerToken
		if up.Auth.BearerEnv != "" {
			token = os.Getenv(up.Auth.BearerEnv)
		}
		if token == "" {
			return nil, fmt.Errorf("upstream %q: service_bearer sem segredo (bearer_env vazio?)", up.Name)
		}
		return &http.Client{Transport: bearerRoundTripper{token: token, next: http.DefaultTransport}}, nil

	case config.SouthAuthServiceOAuthCC:
		clientID := os.Getenv(up.Auth.OAuth.ClientIDEnv)
		clientSecret := os.Getenv(up.Auth.OAuth.ClientSecretEnv)
		if clientID == "" || clientSecret == "" {
			return nil, fmt.Errorf("upstream %q: service_oauth_cc sem client id/secret nas envs", up.Name)
		}
		cc := &clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     up.Auth.OAuth.TokenURL,
			Scopes:       up.Auth.OAuth.Scopes,
		}
		// O Client renova o token sozinho; o segredo nunca chega ao agente.
		return cc.Client(context.Background()), nil

	case config.SouthAuthPerUser:
		var discovery string
		if up.Auth.DiscoveryBearerEnv != "" {
			discovery = os.Getenv(up.Auth.DiscoveryBearerEnv)
		}
		return &http.Client{Transport: perUserRoundTripper{
			upstream:        up.Name,
			discoveryBearer: discovery,
			next:            http.DefaultTransport,
		}}, nil

	default:
		return nil, fmt.Errorf("upstream %q: auth.type %q não suportado", up.Name, typ)
	}
}

// perUserRoundTripper injeta a credencial DO PRINCIPAL na request ao upstream e
// garante o no-passthrough: remove qualquer Authorization herdado antes de
// (talvez) setar o do usuário. Sem credencial no context (boot/descoberta), usa
// o discoveryBearer se houver — nunca o token do norte.
type perUserRoundTripper struct {
	upstream        string
	discoveryBearer string
	next            http.RoundTripper
}

func (rt perUserRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	// NO-PASSTHROUGH (SAFE-T1307/1308): o bearer do leg norte NUNCA vai ao
	// upstream. Removemos qualquer Authorization antes de decidir o que injetar.
	r.Header.Del("Authorization")

	if cred, ok := credstore.FromContext(req.Context()); ok {
		r.Header.Set("Authorization", "Bearer "+cred.Bearer)
	} else if rt.discoveryBearer != "" {
		// Boot (connect + tools/list): credencial de descoberta de baixo
		// privilégio, usada só para listar tools — nunca para agir por conta.
		r.Header.Set("Authorization", "Bearer "+rt.discoveryBearer)
	}
	return rt.next.RoundTrip(r)
}
