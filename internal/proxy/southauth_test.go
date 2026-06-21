package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/danilomendes/mcpgate/internal/audit"
	"github.com/danilomendes/mcpgate/internal/auth"
	"github.com/danilomendes/mcpgate/internal/config"
	"github.com/danilomendes/mcpgate/internal/credstore"
	"github.com/danilomendes/mcpgate/internal/policy"
)

// captureRT registra a última request e devolve uma resposta vazia 200.
type captureRT struct {
	mu   sync.Mutex
	last *http.Request
}

func (c *captureRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.last = req
	c.mu.Unlock()
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}

func (c *captureRT) header(key string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last.Header.Get(key)
}

// TestPerUserRoundTripperInjectionAndNoPassthrough cobre o coração do E4-sul: a
// credencial DO PRINCIPAL é injetada e o bearer do norte NUNCA é repassado.
func TestPerUserRoundTripperInjectionAndNoPassthrough(t *testing.T) {
	newReq := func(ctx context.Context, northToken string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://upstream.test/mcp", nil)
		if northToken != "" {
			r.Header.Set("Authorization", "Bearer "+northToken)
		}
		return r.WithContext(ctx)
	}

	t.Run("injeta credencial do principal e remove o token do norte", func(t *testing.T) {
		crt := &captureRT{}
		rt := perUserRoundTripper{upstream: "github", next: crt}
		ctx := credstore.WithCredential(context.Background(), credstore.Credential{Ref: "mem:github/alice", Bearer: "alice-pat"})

		if _, err := rt.RoundTrip(newReq(ctx, "NORTH-BEARER-DO-AGENTE")); err != nil {
			t.Fatalf("roundtrip: %v", err)
		}
		if got := crt.header("Authorization"); got != "Bearer alice-pat" {
			t.Fatalf("Authorization = %q, quer 'Bearer alice-pat' (token do norte vazou?)", got)
		}
	})

	t.Run("sem credencial e sem discovery: nenhum Authorization (no-passthrough)", func(t *testing.T) {
		crt := &captureRT{}
		rt := perUserRoundTripper{upstream: "github", next: crt}
		if _, err := rt.RoundTrip(newReq(context.Background(), "NORTH-BEARER")); err != nil {
			t.Fatalf("roundtrip: %v", err)
		}
		if got := crt.header("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, quer vazio (token do norte NÃO pode ser repassado)", got)
		}
	})

	t.Run("boot usa discovery bearer, nunca o do norte", func(t *testing.T) {
		crt := &captureRT{}
		rt := perUserRoundTripper{upstream: "github", discoveryBearer: "disco-token", next: crt}
		if _, err := rt.RoundTrip(newReq(context.Background(), "NORTH-BEARER")); err != nil {
			t.Fatalf("roundtrip: %v", err)
		}
		if got := crt.header("Authorization"); got != "Bearer disco-token" {
			t.Fatalf("Authorization = %q, quer 'Bearer disco-token'", got)
		}
	})
}

// buildPerUserProxy monta um Proxy com pipeline completo, um upstream "github"
// per_user em memória, e o credStore/southAuth dados.
func buildPerUserProxy(ctx context.Context, t *testing.T, principal string, store credstore.Store, auditLog *audit.Logger) *mcp.ClientSession {
	t.Helper()
	up := newMultiToolUpstream(ctx, t)

	cfg := &config.Config{
		DefaultAgent: principal,
		Policy:       config.Policy{Default: config.PolicyAllow},
	}
	p := &Proxy{
		cfg:       cfg,
		auditLog:  auditLog,
		server:    mcp.NewServer(&mcp.Implementation{Name: "mcpgate", Version: "test"}, nil),
		resolver:  auth.NewStaticResolver(principal),
		limiter:   newPerAgentLimiter(cfg.RateLimit),
		engine:    policy.NewEngine(cfg.Policy),
		credStore: store,
		southAuth: map[string]config.UpstreamAuth{"github": {Type: config.SouthAuthPerUser}},
	}
	p.server.AddReceivingMiddleware(p.resolveMiddleware, p.discoveryMiddleware, p.rateLimitMiddleware, p.policyMiddleware, p.southAuthMiddleware)

	list, err := up.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, tool := range list.Tools {
		p.registerTool("github", up, tool)
	}

	gSrvT, gCliT := mcp.NewInMemoryTransports()
	if _, err := p.server.Connect(ctx, gSrvT, nil); err != nil {
		t.Fatalf("gateway connect: %v", err)
	}
	agent := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "test"}, nil)
	sess, err := agent.Connect(ctx, gCliT, nil)
	if err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

// TestSouthAuthFailClosed prova que, sem credencial sul para o principal, a
// chamada é NEGADA (nunca cai na conta de serviço nem na de outro usuário) e o
// deny é auditado.
func TestSouthAuthFailClosed(t *testing.T) {
	ctx := context.Background()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog := newAudit(t, auditPath)

	// Store vazio: "charlie" não tem credencial em github.
	agent := buildPerUserProxy(ctx, t, "charlie", credstore.NewMemoryStore("mem"), auditLog)

	_, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "github.echo", Arguments: map[string]any{"message": "oi"}})
	if err == nil {
		t.Fatal("chamada sem credencial sul deveria ser negada (fail-closed)")
	}
	if !strings.Contains(err.Error(), "credencial de upstream") {
		t.Fatalf("erro %q não parece fail-closed do leg sul", err)
	}

	recs := readAuditLines(t, auditPath)
	if len(recs) != 1 || recs[0]["decision"] != audit.DecisionDeny || recs[0]["error"] != "no_south_credential" {
		t.Fatalf("auditoria = %+v, quer 1 deny no_south_credential", recs)
	}
}

// TestSouthAuthIdentityAwareAudit prova que, com credencial, a chamada passa e a
// auditoria registra QUAL credencial de usuário foi usada (a referência, sem segredo).
func TestSouthAuthIdentityAwareAudit(t *testing.T) {
	ctx := context.Background()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog := newAudit(t, auditPath)

	store := credstore.NewMemoryStore("mem")
	store.Put("github", "alice", "alice-pat-SECRETO")
	agent := buildPerUserProxy(ctx, t, "alice", store, auditLog)

	if _, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "github.echo", Arguments: map[string]any{"message": "oi"}}); err != nil {
		t.Fatalf("alice com credencial deveria passar: %v", err)
	}

	recs := readAuditLines(t, auditPath)
	if len(recs) != 1 {
		t.Fatalf("esperava 1 linha, got %d", len(recs))
	}
	if recs[0]["upstream_cred"] != "mem:github/alice" {
		t.Errorf("upstream_cred = %v, quer mem:github/alice", recs[0]["upstream_cred"])
	}
	// O segredo NUNCA pode aparecer na auditoria.
	for _, r := range recs {
		for k, v := range r {
			if s, ok := v.(string); ok && strings.Contains(s, "SECRETO") {
				t.Fatalf("segredo vazou na auditoria em %q: %q", k, s)
			}
		}
	}
}

// TestSouthAuthHTTPInjection é a prova ponta a ponta sobre HTTP real: a request
// que CHEGA ao upstream carrega a credencial do principal (alice), provando a
// injeção delegada no seam sul.
func TestSouthAuthHTTPInjection(t *testing.T) {
	ctx := context.Background()

	// Upstream MCP real servido por httptest, com um handler que captura o
	// Authorization de cada request recebida.
	upSrv := mcp.NewServer(&mcp.Implementation{Name: "github", Version: "test"}, nil)
	mcp.AddTool(upSrv, &mcp.Tool{Name: "echo", Description: "ecoa"},
		func(_ context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: in.Message}}}, nil, nil
		})
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return upSrv }, nil)

	var mu sync.Mutex
	var seen []string
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		mcpHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(httpSrv.Close)

	auditLog := newAudit(t, filepath.Join(t.TempDir(), "audit.jsonl"))
	store := credstore.NewMemoryStore("mem")
	store.Put("github", "alice", "alice-pat")

	cfg := &config.Config{DefaultAgent: "alice", Policy: config.Policy{Default: config.PolicyAllow}}
	p := &Proxy{
		cfg:       cfg,
		auditLog:  auditLog,
		server:    mcp.NewServer(&mcp.Implementation{Name: "mcpgate", Version: "test"}, nil),
		resolver:  auth.NewStaticResolver("alice"),
		limiter:   newPerAgentLimiter(cfg.RateLimit),
		engine:    policy.NewEngine(cfg.Policy),
		credStore: store,
		southAuth: map[string]config.UpstreamAuth{"github": {Type: config.SouthAuthPerUser}},
	}
	p.server.AddReceivingMiddleware(p.resolveMiddleware, p.discoveryMiddleware, p.rateLimitMiddleware, p.policyMiddleware, p.southAuthMiddleware)

	// Conecta o gateway ao upstream HTTP real (constrói o perUserRoundTripper).
	up := config.Upstream{Name: "github", Transport: config.TransportHTTP, URL: httpSrv.URL, Auth: config.UpstreamAuth{Type: config.SouthAuthPerUser}}
	if err := p.connectUpstream(ctx, up); err != nil {
		t.Fatalf("connectUpstream: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	// Agente em memória chama a tool; o forward sai sobre HTTP ao upstream.
	gSrvT, gCliT := mcp.NewInMemoryTransports()
	if _, err := p.server.Connect(ctx, gSrvT, nil); err != nil {
		t.Fatalf("gw connect: %v", err)
	}
	agent := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "test"}, nil)
	sess, err := agent.Connect(ctx, gCliT, nil)
	if err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	if _, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "github.echo", Arguments: map[string]any{"message": "oi"}}); err != nil {
		t.Fatalf("call: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	sawAlice := false
	for _, a := range seen {
		if a == "Bearer alice-pat" {
			sawAlice = true
		}
		if strings.Contains(a, "NORTH") {
			t.Fatalf("token do norte vazou ao upstream: %q", a)
		}
	}
	if !sawAlice {
		t.Fatalf("upstream nunca recebeu a credencial de alice; viu: %v", seen)
	}
}
