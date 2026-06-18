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
//  5. sobe o servidor em stdio.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/danilomendes/mcpgate/internal/audit"
	"github.com/danilomendes/mcpgate/internal/config"
)

const version = "0.1.0"

// namespaceSep separa o nome do upstream do nome da tool no nome namespaced.
// Casa com o formato de política (allow_tools: ["github.list_issues"]).
const namespaceSep = "."

// Proxy mantém o estado do gateway em execução: o servidor voltado ao agente,
// as sessões dos upstreams e o logger de auditoria.
type Proxy struct {
	cfg      *config.Config
	auditLog *audit.Logger
	server   *mcp.Server
	sessions []*mcp.ClientSession // mantidas para fechar no shutdown
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
	}

	// Seam de extensão: os próximos estágios entram como receiving middleware
	// aqui — E2 (RBAC), E4 (identidade) e E5 (inspeção/guardrails). No MVP é só
	// um passthrough leve, deixado plugado e documentado de propósito.
	p.server.AddReceivingMiddleware(tracingMiddleware)

	if len(cfg.Policies) > 0 {
		auditLog.Slog().Warn("política configurada mas ignorada: o motor de política ainda não existe (E2)",
			"policies", len(cfg.Policies))
	}

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
		rec := audit.Record{
			RequestID: audit.NewRequestID(),
			Upstream:  upstream,
			Tool:      namespacedName,
			Identity:  audit.IdentityAnonymous,
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

// Run sobe o servidor do gateway em stdio. Bloqueia até a desconexão do agente
// ou o cancelamento do contexto.
func (p *Proxy) Run(ctx context.Context) error {
	return p.server.Run(ctx, &mcp.StdioTransport{})
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

// tracingMiddleware é o no-op (tracing leve) que ocupa o seam de extensão.
// Os estágios E2/E4/E5 substituirão/encadearão middlewares aqui. Mantido como
// MethodHandler passthrough para deixar o ponto de injeção plugado.
func tracingMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		return next(ctx, method, req)
	}
}
