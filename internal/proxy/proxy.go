// Package proxy é o estágio 5 do gateway: roteia cada tools/call para o
// upstream certo e devolve o resultado intacto ao agente.
//
// No MVP o passthrough é verbatim: o schema de cada ferramenta e os argumentos
// de cada chamada são repassados ao upstream sem reinterpretação. O gateway não
// inventa, não valida e não reescreve schema de tool.
//
// Boot do serve:
//  1. conecta a cada upstream (CommandTransport p/ stdio, StreamableClient p/ http);
//  2. descobre as tools via ListTools (uma vez, no boot);
//  3. registra cada tool no mcp.Server com nome namespaced (<upstream>.<tool>) e
//     o InputSchema copiado verbatim;
//  4. o handler de forward chama o upstream com o nome ORIGINAL e audita;
//  5. sobe o servidor no transporte norte escolhido (http por default, ou stdio).
//
// Importante sobre o ciclo de vida das conexões: as sessões dos upstreams (leg
// sul) são abertas UMA vez, no boot (passos 1–2), e ficam ABERTAS por toda a
// vida do processo. Cada tools/call do agente reaproveita a sessão já aberta —
// não há reconexão por chamada. O transporte norte (leg norte, http/stdio) é
// independente disso: o mesmo *mcp.Server serve qualquer transporte.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/danilomendes/mcpgate/internal/audit"
	"github.com/danilomendes/mcpgate/internal/auth"
	"github.com/danilomendes/mcpgate/internal/config"
	"github.com/danilomendes/mcpgate/internal/policy"
)

// Códigos JSON-RPC do range reservado a erros de servidor (-32000..-32099).
// O agente recebe uma resposta de erro bem-formada — nunca panic nem queda de
// conexão.
const (
	codePolicyDenied = -32001 // acesso negado pelo RBAC (estágio 2)
	codeRateLimited  = -32002 // admissão negada por quota (SAFE-MCP/Impact, ATK-TA0040)
)

// methodCallTool é o método JSON-RPC interceptado pelos middlewares de admissão
// e RBAC. Demais métodos (initialize, tools/list, ping) passam direto.
const methodCallTool = "tools/call"

// httpShutdownTimeout limita o tempo de drenagem do servidor HTTP no shutdown
// gracioso (ctx cancelado por SIGINT/SIGTERM).
const httpShutdownTimeout = 5 * time.Second

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
}

// New conecta a todos os upstreams, descobre e registra suas tools, e devolve
// um Proxy pronto para Run. O caller deve chamar Close ao final.
//
// Se a inicialização falhar no meio, as sessões já abertas são fechadas antes
// de retornar o erro — nada de processo upstream vazado.
func New(ctx context.Context, cfg *config.Config, auditLog *audit.Logger) (*Proxy, error) {
	p := &Proxy{
		cfg:      cfg,
		auditLog: auditLog,
		server:   mcp.NewServer(&mcp.Implementation{Name: "mcpgate", Version: version}, nil),
		resolver: auth.NewStaticResolver(cfg.DefaultAgent),
		limiter:  newPerAgentLimiter(cfg.RateLimit),
		engine:   policy.NewEngine(cfg.Policy),
	}

	// Pipeline de governança (estágio 2). AddReceivingMiddleware(m1,m2,m3) executa
	// m1 mais externo, então a ordem aqui É a ordem de execução:
	//   resolver (identidade) -> rate limit (admissão) -> RBAC -> forward -> auditoria.
	// A auditoria é o último elo: allow é auditado no forwardHandler; deny é
	// auditado no próprio middleware que barrou (1 linha por tools/call, sempre).
	p.server.AddReceivingMiddleware(
		p.resolveMiddleware,
		p.rateLimitMiddleware,
		p.policyMiddleware,
	)

	for _, up := range cfg.Upstreams {
		if err := p.connectUpstream(ctx, up); err != nil {
			_ = p.Close()
			return nil, fmt.Errorf("upstream %q: %w", up.Name, err)
		}
	}

	return p, nil
}

// connectUpstream abre a sessão com um upstream, lista suas tools e registra
// cada uma no servidor do gateway.
func (p *Proxy) connectUpstream(ctx context.Context, up config.Upstream) error {
	transport, err := buildTransport(up)
	if err != nil {
		return err
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "mcpgate", Version: version}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	p.sessions = append(p.sessions, session)

	list, err := session.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("tools/list: %w", err)
	}

	for _, tool := range list.Tools {
		p.registerTool(up.Name, session, tool)
	}

	p.auditLog.Slog().Info("upstream conectado",
		"upstream", up.Name, "transport", up.Transport, "tools", len(list.Tools))
	return nil
}

// registerTool publica uma tool do upstream no servidor do gateway, com o nome
// namespaced e o schema copiado verbatim, e instala o handler de forward.
func (p *Proxy) registerTool(upstream string, session *mcp.ClientSession, src *mcp.Tool) {
	// Cópia rasa do *mcp.Tool, trocando apenas o Name pela versão namespaced.
	// O InputSchema (e demais campos) vai verbatim do upstream para o agente.
	namespaced := *src
	originalName := src.Name
	namespaced.Name = upstream + namespaceSep + originalName

	handler := p.forwardHandler(upstream, namespaced.Name, originalName, session)
	p.server.AddTool(&namespaced, handler)
}

// forwardHandler devolve o ToolHandler que repassa a chamada ao upstream,
// mede a duração e emite a linha de auditoria. Captura a sessão do upstream e
// o nome ORIGINAL (sem prefixo) da tool.
func (p *Proxy) forwardHandler(upstream, namespacedName, originalName string, session *mcp.ClientSession) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		// Chegou aqui => passou pelo rate limit e pelo RBAC: decisão = allow.
		// O principal foi resolvido e posto no context pelo resolveMiddleware.
		rec := audit.Record{
			RequestID: audit.NewRequestID(),
			Upstream:  upstream,
			Tool:      namespacedName,
			Identity:  auth.PrincipalFromContext(ctx),
			Decision:  audit.DecisionAllow,
			ArgKeys:   argKeys(req.Params.Arguments),
		}

		// Repasse verbatim dos argumentos: json.RawMessage serializa para si
		// mesma, então não há round-trip lossy ao colocá-la em Arguments (any).
		result, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name:      originalName,
			Arguments: req.Params.Arguments,
		})

		rec.DurationMS = time.Since(start).Milliseconds()
		if err != nil {
			rec.OK = false
			rec.Error = err.Error()
			p.auditLog.Emit(rec)
			// Erro de transporte → erro de protocolo limpo ao agente.
			return nil, fmt.Errorf("encaminhando para upstream %q: %w", upstream, err)
		}

		// Sucesso a nível de transporte. Um erro a nível de tool (IsError) é um
		// resultado válido e segue intacto ao agente — não é falha do proxy.
		rec.OK = true
		p.auditLog.Emit(rec)
		return result, nil
	}
}

// Server expõe o *mcp.Server construído no boot. É o ponto único que o
// callback getServer do StreamableHTTPHandler consome (mesma instância para
// todo request) e que o transporte stdio roda — a lógica do server não é
// duplicada por transporte.
func (p *Proxy) Server() *mcp.Server { return p.server }

// RunStdio sobe o servidor do gateway no transporte stdio. Bloqueia até a
// desconexão do agente ou o cancelamento do contexto. Útil em cenário
// laptop/single-user; o leg sul (upstreams) é indiferente a esta escolha.
func (p *Proxy) RunStdio(ctx context.Context) error {
	p.auditLog.Slog().Info("gateway ouvindo", "transport", "stdio")
	return p.server.Run(ctx, &mcp.StdioTransport{})
}

// RunHTTP sobe o servidor do gateway no transporte Streamable HTTP, servido por
// net/http em addr. Bloqueia até o cancelamento do contexto (SIGINT/SIGTERM),
// quando drena as conexões com shutdown gracioso.
//
// Usa os defaults do SDK: sem EventStore, sem modo stateless, sem sessões
// persistentes (E4/E10/E11). O mesmo *mcp.Server é devolvido a cada request —
// as sessões dos upstreams, abertas no boot, são compartilhadas por todos.
func (p *Proxy) RunHTTP(ctx context.Context, addr string) error {
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return p.server
	}, nil)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second, // mitiga slowloris (Slowloris/DoS)
	}

	// Shutdown gracioso: quando o ctx é cancelado, drena as conexões em vez de
	// derrubá-las no meio. ListenAndServe então retorna http.ErrServerClosed.
	// context.Background() abaixo é proposital: o ctx de request já está cancelado
	// (foi o que disparou o shutdown); a drenagem precisa do seu próprio prazo.
	go func() { //nolint:gosec // G118: shutdown context deve ser independente do ctx já cancelado
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	p.auditLog.Slog().Info("gateway ouvindo", "transport", "http", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

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

// buildTransport monta o transporte do cliente para um upstream conforme o tipo.
func buildTransport(up config.Upstream) (mcp.Transport, error) {
	switch up.Transport {
	case config.TransportStdio:
		// O SDK sobe o processo (exec.Command) e fala stdin/stdout com ele.
		cmd := exec.Command(up.Command[0], up.Command[1:]...) //nolint:gosec // argv vem da config local do operador
		return &mcp.CommandTransport{Command: cmd}, nil
	case config.TransportHTTP:
		return &mcp.StreamableClientTransport{Endpoint: up.URL}, nil
	default:
		return nil, fmt.Errorf("transport %q não suportado", up.Transport)
	}
}

// argKeys extrai apenas as CHAVES dos argumentos crus, nunca os valores, para
// não vazar PII no log no MVP. Argumentos ausentes ou não-objeto → nil.
func argKeys(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil // não é um objeto JSON; nada de chaves a registrar
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// resolveMiddleware resolve o principal (identidade) e o injeta no context, para
// que os estágios seguintes o leiam de lá. No E2 o resolver é estático; o E4 só
// troca o resolver. Aplica-se a todos os métodos.
func (p *Proxy) resolveMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		ctx = auth.WithPrincipal(ctx, p.resolver.Resolve(ctx))
		return next(ctx, method, req)
	}
}

// rateLimitMiddleware é a admissão por agente (token bucket). Estoura => erro
// JSON-RPC limpo (codeRateLimited); a conexão segue viva. Só age em tools/call.
func (p *Proxy) rateLimitMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if method != methodCallTool || !p.limiter.enabled() {
			return next(ctx, method, req)
		}
		principal := auth.PrincipalFromContext(ctx)
		if !p.limiter.allow(principal) {
			tool := callToolName(req)
			p.auditDeny(principal, tool, "rate_limited")
			return nil, &jsonrpc.Error{
				Code:    codeRateLimited,
				Message: fmt.Sprintf("rate limit excedido para o agente %q", principal),
			}
		}
		return next(ctx, method, req)
	}
}

// policyMiddleware é o RBAC por ferramenta (default-deny). Nega => erro JSON-RPC
// limpo (codePolicyDenied), sem repassar ao upstream. Só age em tools/call; a
// tool negada continua visível no tools/list (filtrar é E3).
func (p *Proxy) policyMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if method != methodCallTool {
			return next(ctx, method, req)
		}
		principal := auth.PrincipalFromContext(ctx)
		tool := callToolName(req)
		if d := p.engine.Evaluate(principal, tool); !d.Allow {
			p.auditDeny(principal, tool, d.Reason)
			return nil, &jsonrpc.Error{
				Code:    codePolicyDenied,
				Message: fmt.Sprintf("acesso negado à tool %q para o agente %q (%s)", tool, principal, d.Reason),
			}
		}
		return next(ctx, method, req)
	}
}

// auditDeny emite a linha de auditoria de uma chamada barrada (rate limit ou
// RBAC), com decision=deny e o principal. É o único ponto de auditoria do
// caminho negado — o caminho allow é auditado no forwardHandler.
func (p *Proxy) auditDeny(principal, tool, reason string) {
	p.auditLog.Emit(audit.Record{
		RequestID: audit.NewRequestID(),
		Upstream:  upstreamOf(tool),
		Tool:      tool,
		Identity:  principal,
		Decision:  audit.DecisionDeny,
		OK:        false,
		Error:     reason,
	})
}

// callToolName extrai o nome (namespaced) da tool de uma requisição tools/call.
func callToolName(req mcp.Request) string {
	if params, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok {
		return params.Name
	}
	return ""
}

// upstreamOf deriva o nome do upstream do nome namespaced da tool (prefixo antes
// do primeiro separador). Vazio se não houver prefixo.
func upstreamOf(tool string) string {
	if i := strings.Index(tool, namespaceSep); i >= 0 {
		return tool[:i]
	}
	return ""
}
