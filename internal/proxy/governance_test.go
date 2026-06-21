package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/danilomendes/mcpgate/internal/audit"
	"github.com/danilomendes/mcpgate/internal/auth"
	"github.com/danilomendes/mcpgate/internal/config"
	"github.com/danilomendes/mcpgate/internal/policy"
)

// newMultiToolUpstream sobe um upstream em memória com echo, add e printEnv.
func newMultiToolUpstream(ctx context.Context, t *testing.T) *mcp.ClientSession {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "upstream", Version: "test"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "echo", Description: "ecoa"},
		func(_ context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: in.Message}}}, nil, nil
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "add", Description: "soma"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ echoArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "nunca chamado"}}}, nil, nil
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "printEnv", Description: "env"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ echoArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "nunca chamado"}}}, nil, nil
		})

	srvT, cliT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, srvT, nil); err != nil {
		t.Fatalf("upstream connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "mcpgate", Version: "test"}, nil)
	sess, err := client.Connect(ctx, cliT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

// buildProxy monta um *Proxy com o pipeline de governança completo (igual a New:
// resolver+verifier de auth, descoberta filtrada, rate limit, RBAC) e um upstream
// "everything" em memória já conectado e registrado.
func buildProxy(ctx context.Context, t *testing.T, cfg *config.Config, auditLog *audit.Logger) *Proxy {
	t.Helper()
	up := newMultiToolUpstream(ctx, t)

	verifier, authOpts, err := auth.NewVerifier(cfg.Auth)
	if err != nil {
		t.Fatalf("auth verifier: %v", err)
	}
	p := &Proxy{
		cfg:      cfg,
		auditLog: auditLog,
		server:   mcp.NewServer(&mcp.Implementation{Name: "mcpgate", Version: "test"}, nil),
		resolver: auth.NewStaticResolver(cfg.DefaultAgent),
		limiter:  newPerAgentLimiter(cfg.RateLimit),
		engine:   policy.NewEngine(cfg.Policy),
		verifier: verifier,
		authOpts: authOpts,
	}
	p.server.AddReceivingMiddleware(p.resolveMiddleware, p.discoveryMiddleware, p.rateLimitMiddleware, p.policyMiddleware)

	list, err := up.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, tool := range list.Tools {
		p.registerTool("everything", up, tool)
	}
	return p
}

// buildGateway devolve uma sessão de agente conectada em memória ao Proxy.
func buildGateway(ctx context.Context, t *testing.T, cfg *config.Config, auditLog *audit.Logger) *mcp.ClientSession {
	t.Helper()
	p := buildProxy(ctx, t, cfg, auditLog)

	gSrvT, gCliT := mcp.NewInMemoryTransports()
	if _, err := p.server.Connect(ctx, gSrvT, nil); err != nil {
		t.Fatalf("gateway connect: %v", err)
	}
	agent := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "test"}, nil)
	agentSession, err := agent.Connect(ctx, gCliT, nil)
	if err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	t.Cleanup(func() { _ = agentSession.Close() })
	return agentSession
}

func smokePolicyConfig() *config.Config {
	return &config.Config{
		DefaultAgent: "anonymous",
		Policy: config.Policy{
			Default:    config.PolicyDeny,
			AllowTools: []string{"everything.echo"},
			DenyTools:  []string{"everything.add"},
		},
	}
}

// TestPolicyDecisionsAndAudit prova allow / deny explícito / default-deny e que
// a auditoria registra decision + principal em cada caso.
func TestPolicyDecisionsAndAudit(t *testing.T) {
	ctx := context.Background()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog := newAudit(t, auditPath)

	agent := buildGateway(ctx, t, smokePolicyConfig(), auditLog)

	// tools/list é filtrado (E3): só a tool permitida (echo) aparece; a negada
	// (add) e a default-deny (printEnv) ficam INVISÍVEIS — não só bloqueadas.
	list, err := agent.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := len(list.Tools); got != 1 {
		t.Fatalf("esperava 1 tool visível (só a permitida), got %d", got)
	}
	if list.Tools[0].Name != "everything.echo" {
		t.Fatalf("esperava só everything.echo visível, got %q", list.Tools[0].Name)
	}

	// 1) allow: echo retorna o resultado real do upstream.
	res, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "everything.echo", Arguments: map[string]any{"message": "oi"}})
	if err != nil {
		t.Fatalf("echo (allow) erro inesperado: %v", err)
	}
	if txt, ok := res.Content[0].(*mcp.TextContent); !ok || txt.Text != "oi" {
		t.Fatalf("echo devolveu %+v, quer 'oi'", res.Content)
	}

	// 2) deny explícito: add é barrado com erro JSON-RPC limpo, sem ir ao upstream.
	if _, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "everything.add", Arguments: map[string]any{"message": "x"}}); err == nil {
		t.Fatal("add (deny) deveria falhar")
	} else if !strings.Contains(err.Error(), "acesso negado") {
		t.Fatalf("add: erro %q não parece deny de política", err)
	}

	// 3) default-deny: printEnv não está em lugar nenhum => negado.
	if _, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "everything.printEnv", Arguments: map[string]any{}}); err == nil {
		t.Fatal("printEnv (default-deny) deveria falhar")
	}

	recs := readAuditLines(t, auditPath)
	if len(recs) != 3 {
		t.Fatalf("esperava 3 linhas de auditoria, got %d", len(recs))
	}
	wantDecision := map[string]string{
		"everything.echo":     audit.DecisionAllow,
		"everything.add":      audit.DecisionDeny,
		"everything.printEnv": audit.DecisionDeny,
	}
	for _, r := range recs {
		tool, _ := r["tool"].(string)
		if r["decision"] != wantDecision[tool] {
			t.Errorf("tool %s: decision = %v, quer %v", tool, r["decision"], wantDecision[tool])
		}
		if r["identity"] != "anonymous" {
			t.Errorf("tool %s: identity = %v, quer anonymous", tool, r["identity"])
		}
	}
}

// TestRateLimitCleanError prova que estourar a quota devolve erro JSON-RPC limpo
// (sem derrubar a conexão) e audita o deny.
func TestRateLimitCleanError(t *testing.T) {
	ctx := context.Background()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog := newAudit(t, auditPath)

	cfg := smokePolicyConfig()
	cfg.RateLimit = config.RateLimit{RPS: 1, Burst: 1} // 1 token; a 2ª chamada estoura
	agent := buildGateway(ctx, t, cfg, auditLog)

	echo := &mcp.CallToolParams{Name: "everything.echo", Arguments: map[string]any{"message": "oi"}}

	// 1ª chamada consome o único token e passa.
	if _, err := agent.CallTool(ctx, echo); err != nil {
		t.Fatalf("1ª chamada deveria passar: %v", err)
	}
	// 2ª chamada imediata: bucket vazio => rate limit.
	_, err := agent.CallTool(ctx, echo)
	if err == nil {
		t.Fatal("2ª chamada deveria ser barrada por rate limit")
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("erro %q não parece rate limit", err)
	}

	// A conexão segue VIVA: ping funciona após o rate limit.
	if err := agent.Ping(ctx, nil); err != nil {
		t.Fatalf("conexão deveria seguir viva após rate limit: %v", err)
	}

	recs := readAuditLines(t, auditPath)
	if len(recs) != 2 {
		t.Fatalf("esperava 2 linhas (allow + deny), got %d", len(recs))
	}
	if recs[1]["decision"] != audit.DecisionDeny || recs[1]["error"] != "rate_limited" {
		t.Errorf("2ª linha = %+v, quer decision=deny error=rate_limited", recs[1])
	}
}

func newAudit(t *testing.T, path string) *audit.Logger {
	t.Helper()
	l, err := audit.New(config.Audit{Sink: config.SinkFile, Path: path})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func readAuditLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // tempdir de teste
	if err != nil {
		t.Fatalf("abrir audit: %v", err)
	}
	defer func() { _ = f.Close() }()

	var recs []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if sc.Text() == "" {
			continue
		}
		var r map[string]any
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("linha de audit não é JSON: %v", err)
		}
		recs = append(recs, r)
	}
	return recs
}
