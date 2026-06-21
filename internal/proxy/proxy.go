// Package proxy é o runtime do gateway: para o agente ele é um mcp.Server; para
// cada upstream, um mcp.Client. Toda tools/call atravessa o pipeline de
// governança e, no fim, o estágio 5 (proxy) encaminha ao upstream certo e devolve
// o resultado intacto. O passthrough é verbatim: o gateway não inventa, não valida
// e não reescreve schema de tool.
//
// O pacote está dividido por responsabilidade (mesmo package proxy):
//   - proxy.go      — tipo Proxy, construção (New) e ciclo de vida (Server, Close)
//   - serve.go      — transporte norte (RunStdio, RunHTTP, httpHandler)
//   - upstream.go   — leg sul (connect/registro/forward + transporte do upstream)
//   - middleware.go — o pipeline (resolve, discovery, rate limit, RBAC + helpers)
//   - ratelimit.go  — token bucket por agente
//
// Ciclo de vida das conexões: as sessões dos upstreams (leg sul) são abertas UMA
// vez, no boot, e ficam ABERTAS por toda a vida do processo — cada tools/call
// reaproveita a sessão já aberta, não há reconexão por chamada. O transporte
// norte é independente disso: o mesmo *mcp.Server serve qualquer transporte.
package proxy

import (
	"context"
	"errors"
	"fmt"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/danilomendes/mcpgate/internal/audit"
	"github.com/danilomendes/mcpgate/internal/auth"
	"github.com/danilomendes/mcpgate/internal/config"
	"github.com/danilomendes/mcpgate/internal/credstore"
	"github.com/danilomendes/mcpgate/internal/policy"
)

const version = "0.1.0"

// namespaceSep separa o nome do upstream do nome da tool no nome namespaced.
// Casa com o formato de política (allow_tools: ["github.list_issues"]).
const namespaceSep = "."

// Proxy mantém o estado do gateway em execução: o servidor voltado ao agente,
// as sessões dos upstreams, o logger de auditoria e o pipeline de governança
// (resolver de identidade, rate limit e motor de política).
type Proxy struct {
	cfg      *config.Config
	auditLog *audit.Logger
	server   *mcp.Server
	sessions []*mcp.ClientSession // mantidas para fechar no shutdown

	resolver auth.Resolver
	limiter  *perAgentLimiter
	engine   *policy.Engine

	// Auth do transporte norte (E4, só HTTP). verifier nil => sem auth: o caminho
	// HTTP segue anônimo, igual ao E2. stdio nunca usa auth.
	verifier sdkauth.TokenVerifier
	authOpts *sdkauth.RequireBearerTokenOptions

	// Auth do transporte sul (E4-sul). credStore resolve a credencial por
	// (principal, upstream) dos upstreams per_user; nil quando nenhum é per_user.
	// southAuth indexa a config de auth sul por nome de upstream, consumida pelo
	// southAuthMiddleware (fail-closed) e por buildTransport (injeção).
	credStore credstore.Store
	southAuth map[string]config.UpstreamAuth
}

// New conecta a todos os upstreams, descobre e registra suas tools, e devolve
// um Proxy pronto para Run. O caller deve chamar Close ao final.
//
// Se a inicialização falhar no meio, as sessões já abertas são fechadas antes
// de retornar o erro — nada de processo upstream vazado.
func New(ctx context.Context, cfg *config.Config, auditLog *audit.Logger) (*Proxy, error) {
	verifier, authOpts, err := auth.NewVerifier(cfg.Auth)
	if err != nil {
		return nil, err
	}

	credStore, err := newCredentialStore(cfg.Credentials)
	if err != nil {
		return nil, err
	}

	p := &Proxy{
		cfg:       cfg,
		auditLog:  auditLog,
		server:    mcp.NewServer(&mcp.Implementation{Name: "mcpgate", Version: version}, nil),
		resolver:  auth.NewStaticResolver(cfg.DefaultAgent),
		limiter:   newPerAgentLimiter(cfg.RateLimit),
		engine:    policy.NewEngine(cfg.Policy),
		verifier:  verifier,
		authOpts:  authOpts,
		credStore: credStore,
		southAuth: southAuthByUpstream(cfg.Upstreams),
	}

	// Pipeline de governança (estágios 1–3). AddReceivingMiddleware(m1,m2,...)
	// executa m1 mais externo, então a ordem aqui É a ordem de execução:
	//   resolver (identidade) -> descoberta filtrada (tools/list) -> rate limit
	//   (admissão) -> RBAC (tools/call) -> forward -> auditoria.
	// O resolver vem primeiro porque todos dependem do principal no context.
	// A descoberta (E3) e o RBAC (E2) compartilham o MESMO Engine: o que some do
	// tools/list é exatamente o que seria negado no tools/call. A auditoria é o
	// último elo: allow é auditado no forwardHandler; deny no middleware que barrou.
	// southAuthMiddleware roda DEPOIS do RBAC (a tool já foi permitida ao
	// principal) e ANTES do forward: resolve a credencial sul por usuário e faz o
	// fail-closed se não houver — a credencial só é buscada para chamadas já
	// autorizadas pela política (menor privilégio / coerência com E2).
	p.server.AddReceivingMiddleware(
		p.resolveMiddleware,
		p.discoveryMiddleware,
		p.rateLimitMiddleware,
		p.policyMiddleware,
		p.southAuthMiddleware,
	)

	for _, up := range cfg.Upstreams {
		if err := p.connectUpstream(ctx, up); err != nil {
			_ = p.Close()
			return nil, fmt.Errorf("upstream %q: %w", up.Name, err)
		}
	}

	return p, nil
}

// Server expõe o *mcp.Server construído no boot. É o ponto único que o
// callback getServer do StreamableHTTPHandler consome (mesma instância para
// todo request) e que o transporte stdio roda — a lógica do server não é
// duplicada por transporte.
func (p *Proxy) Server() *mcp.Server { return p.server }

// Close fecha todas as sessões dos upstreams (encerrando os processos stdio).
func (p *Proxy) Close() error {
	var errs []error
	for _, s := range p.sessions {
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
