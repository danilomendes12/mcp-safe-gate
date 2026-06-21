package proxy

// middleware.go — o pipeline de governança (receiving middleware do mcp.Server).
// AddReceivingMiddleware(m1,m2,...) executa m1 mais externo, então a ordem de
// registro em New é a ordem de execução:
//
//	resolve (identidade) -> discovery (tools/list) -> rateLimit -> policy -> forward
//
// resolve roda em todo método (põe o principal no context); discovery só age em
// tools/list; rateLimit e policy só agem em tools/call. A auditoria do caminho
// negado mora aqui (auditDeny); a do caminho allow, no forwardHandler.

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/danilomendes/mcpgate/internal/audit"
	"github.com/danilomendes/mcpgate/internal/auth"
)

// Códigos JSON-RPC do range reservado a erros de servidor (-32000..-32099).
// O agente recebe uma resposta de erro bem-formada — nunca panic nem queda de
// conexão.
const (
	codePolicyDenied = -32001 // acesso negado pelo RBAC (estágio 2)
	codeRateLimited  = -32002 // admissão negada por quota (SAFE-MCP/Impact, ATK-TA0040)
)

// Métodos JSON-RPC interceptados pelos middlewares: methodCallTool pela admissão
// e RBAC (estágio 2), methodListTools pela descoberta filtrada (estágio 3).
// Demais métodos (initialize, ping) passam direto.
const (
	methodCallTool  = "tools/call"
	methodListTools = "tools/list"
)

// resolveMiddleware resolve o principal (identidade) e o injeta no context, para
// que os estágios seguintes o leiam de lá. Aplica-se a todos os métodos.
//
// No caminho HTTP autenticado (E4), o middleware RequireBearerToken do SDK já
// verificou o bearer e anexou o TokenInfo ao req.Extra; daí sai o principal real
// (SAFE-T1307, confused deputy: o gateway age pela identidade verificada, não
// repassa cegamente). Sem TokenInfo (stdio, ou HTTP sem auth) cai no resolver
// estático: default_agent ou "anonymous".
func (p *Proxy) resolveMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		ctx = auth.WithPrincipal(ctx, p.resolvePrincipal(ctx, req))
		return next(ctx, method, req)
	}
}

// resolvePrincipal extrai o principal do TokenInfo da request (HTTP autenticado)
// ou cai no resolver estático (stdio / HTTP sem auth).
func (p *Proxy) resolvePrincipal(ctx context.Context, req mcp.Request) string {
	if extra := req.GetExtra(); extra != nil && extra.TokenInfo != nil {
		return auth.PrincipalFromTokenInfo(extra.TokenInfo)
	}
	return p.resolver.Resolve(ctx)
}

// discoveryMiddleware é a descoberta filtrada (estágio 3 / E3): intercepta
// tools/list, chama o handler e remove do resultado as tools que o principal não
// pode ver. A decisão usa o MESMO Engine do RBAC, então a tool negada fica
// INVISÍVEL na listagem — não só bloqueada no tools/call. Mitiga enumeração de
// tools e capability mapping (SAFE-T1602). Só age em tools/list; demais métodos
// passam direto.
func (p *Proxy) discoveryMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if err != nil || method != methodListTools {
			return res, err
		}
		list, ok := res.(*mcp.ListToolsResult)
		if !ok {
			return res, err
		}
		principal := auth.PrincipalFromContext(ctx)
		// Slice nova (não mutar o backing array do handler); ponteiros *Tool são
		// compartilhados mas só lidos, nunca alterados.
		kept := make([]*mcp.Tool, 0, len(list.Tools))
		for _, t := range list.Tools {
			if p.engine.Evaluate(principal, t.Name).Allow {
				kept = append(kept, t)
			}
		}
		list.Tools = kept
		return list, nil
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
// tool negada já some do tools/list pelo discoveryMiddleware (E3) — aqui ela
// também é rejeitada se chamada direto (invisível E bloqueada).
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
