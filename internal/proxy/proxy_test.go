package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/danilomendes/mcpgate/internal/audit"
	"github.com/danilomendes/mcpgate/internal/config"
)

// echoArgs é o input da tool de teste do upstream fake.
type echoArgs struct {
	Message string `json:"message" jsonschema:"a mensagem para ecoar"`
}

// newUpstreamSession sobe um servidor MCP upstream em memória com uma única
// tool `echo` e devolve uma sessão de cliente já conectada a ele.
func newUpstreamSession(ctx context.Context, t *testing.T) *mcp.ClientSession {
	t.Helper()

	srv := mcp.NewServer(&mcp.Implementation{Name: "upstream", Version: "test"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "echo", Description: "ecoa a mensagem"},
		func(_ context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: in.Message}},
			}, nil, nil
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

// TestForwardPassthroughAndAudit é a prova end-to-end (sem rede) do MVP:
// namespacing, passthrough verbatim do resultado e uma linha de auditoria.
func TestForwardPassthroughAndAudit(t *testing.T) {
	ctx := context.Background()

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := audit.New(config.Audit{Sink: config.SinkFile, Path: auditPath})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	upSession := newUpstreamSession(ctx, t)

	// Monta um Proxy e registra as tools do upstream manualmente (replicando o
	// que connectUpstream faz, mas sem precisar de config/transporte real).
	p := &Proxy{
		cfg:      &config.Config{},
		auditLog: auditLog,
		server:   mcp.NewServer(&mcp.Implementation{Name: "mcpgate", Version: "test"}, nil),
	}
	list, err := upSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, tool := range list.Tools {
		p.registerTool("up", upSession, tool)
	}

	// Conecta um "agente" ao servidor do gateway, também em memória.
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

	// tools/list do gateway deve expor o nome namespaced.
	gList, err := agentSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("agent list: %v", err)
	}
	if len(gList.Tools) != 1 || gList.Tools[0].Name != "up.echo" {
		t.Fatalf("esperava tool 'up.echo', got: %+v", gList.Tools)
	}

	// Chamar a tool namespaced deve retornar o resultado real do upstream.
	res, err := agentSession.CallTool(ctx, &mcp.CallToolParams{
		Name:      "up.echo",
		Arguments: map[string]any{"message": "ola"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("resultado inesperadamente IsError: %+v", res)
	}
	txt, ok := res.Content[0].(*mcp.TextContent)
	if !ok || txt.Text != "ola" {
		t.Fatalf("esperava eco 'ola', got: %+v", res.Content)
	}

	// Exatamente uma linha de auditoria, com os campos esperados.
	rec := readSingleAuditRecord(t, auditPath)
	if rec["tool"] != "up.echo" {
		t.Errorf("tool = %v, quer up.echo", rec["tool"])
	}
	if rec["upstream"] != "up" {
		t.Errorf("upstream = %v, quer up", rec["upstream"])
	}
	if rec["identity"] != audit.IdentityAnonymous {
		t.Errorf("identity = %v, quer %s", rec["identity"], audit.IdentityAnonymous)
	}
	if rec["ok"] != true {
		t.Errorf("ok = %v, quer true", rec["ok"])
	}
	if rec["ts"] == nil || rec["request_id"] == nil || rec["duration_ms"] == nil {
		t.Errorf("campos obrigatórios faltando: %+v", rec)
	}
	// arg_keys deve conter apenas a chave, nunca o valor "ola".
	keys, _ := rec["arg_keys"].([]any)
	if len(keys) != 1 || keys[0] != "message" {
		t.Errorf("arg_keys = %v, quer [message]", rec["arg_keys"])
	}
}

func readSingleAuditRecord(t *testing.T, path string) map[string]any {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // path é um tempdir de teste
	if err != nil {
		t.Fatalf("abrir audit: %v", err)
	}
	defer func() { _ = f.Close() }()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if sc.Text() != "" {
			lines = append(lines, sc.Text())
		}
	}
	if len(lines) != 1 {
		t.Fatalf("esperava 1 linha de auditoria, got %d: %v", len(lines), lines)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("audit não é JSON: %v", err)
	}
	return rec
}

func TestArgKeysRedaction(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"objeto", `{"token":"secret","user":"x"}`, []string{"token", "user"}},
		{"vazio", ``, nil},
		{"nao-objeto", `[1,2,3]`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := argKeys(json.RawMessage(tt.raw))
			slices.Sort(got)
			want := slices.Clone(tt.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("argKeys(%q) = %v, quer %v", tt.raw, got, want)
			}
		})
	}
}
