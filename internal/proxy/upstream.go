package proxy

// upstream.go — leg SUL (gateway como mcp.Client de cada upstream): conexão e
// descoberta no boot, registro das tools com nome namespaced, encaminhamento
// verbatim de cada tools/call e a injeção opcional de bearer no upstream HTTP.
//
// As sessões dos upstreams são abertas UMA vez, no boot, e ficam vivas por todo
// o processo — cada tools/call reaproveita a sessão, não há reconexão por chamada.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/danilomendes/mcpgate/internal/audit"
	"github.com/danilomendes/mcpgate/internal/auth"
	"github.com/danilomendes/mcpgate/internal/config"
)

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

// buildTransport monta o transporte do cliente para um upstream conforme o tipo.
func buildTransport(up config.Upstream) (mcp.Transport, error) {
	switch up.Transport {
	case config.TransportStdio:
		// O SDK sobe o processo (exec.Command) e fala stdin/stdout com ele.
		cmd := exec.Command(up.Command[0], up.Command[1:]...) //nolint:gosec // argv vem da config local do operador
		return &mcp.CommandTransport{Command: cmd}, nil
	case config.TransportHTTP:
		t := &mcp.StreamableClientTransport{Endpoint: up.URL}
		// Auth sul (E4): se o upstream exige bearer, injetamos o segredo no leg
		// sul via http.Client. O segredo fica só entre gateway e upstream — NUNCA
		// chega ao agente (que fala apenas o leg norte).
		if up.BearerToken != "" {
			t.HTTPClient = &http.Client{Transport: bearerRoundTripper{
				token: up.BearerToken,
				next:  http.DefaultTransport,
			}}
		}
		return t, nil
	default:
		return nil, fmt.Errorf("transport %q não suportado", up.Transport)
	}
}

// bearerRoundTripper injeta `Authorization: Bearer <token>` em cada requisição
// ao upstream. Clona a request antes de mutar os headers, conforme o contrato do
// http.RoundTripper (não modificar a request recebida).
type bearerRoundTripper struct {
	token string
	next  http.RoundTripper
}

func (b bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
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
