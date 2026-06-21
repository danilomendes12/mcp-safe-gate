package proxy

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/danilomendes/mcpgate/internal/config"
)

// discoveryConfig dá a cada principal um subconjunto distinto das tools do
// upstream (echo, add, printEnv), com postura global default-deny.
func discoveryConfig(defaultAgent string) *config.Config {
	return &config.Config{
		DefaultAgent: defaultAgent,
		Policy: config.Policy{
			Default: config.PolicyDeny,
			Agents: map[string]config.AgentPolicy{
				"alice": {AllowTools: []string{"everything.echo", "everything.add"}},
				"bob":   {AllowTools: []string{"everything.printEnv"}},
			},
		},
	}
}

// TestFilteredDiscoveryPerPrincipal prova o E3: cada principal vê só as tools que
// pode chamar; a tool fora do seu escopo fica INVISÍVEL no tools/list E é
// rejeitada com erro JSON-RPC limpo se chamada direto; anonymous (sem regra, no
// default-deny global) não vê nada.
func TestFilteredDiscoveryPerPrincipal(t *testing.T) {
	tests := []struct {
		name        string
		agent       string
		wantVisible []string
		// hiddenCall é uma tool que o principal NÃO pode ver; chamá-la direto deve
		// falhar (invisível e bloqueada). Vazio => pula a checagem.
		hiddenCall string
	}{
		{
			name:        "alice vê seu subconjunto",
			agent:       "alice",
			wantVisible: []string{"everything.add", "everything.echo"},
			hiddenCall:  "everything.printEnv",
		},
		{
			name:        "bob vê outro subconjunto",
			agent:       "bob",
			wantVisible: []string{"everything.printEnv"},
			hiddenCall:  "everything.echo",
		},
		{
			name:        "anonymous no default-deny não vê nada",
			agent:       "anonymous",
			wantVisible: nil,
			hiddenCall:  "everything.echo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			auditLog := newAudit(t, filepath.Join(t.TempDir(), "audit.jsonl"))
			agent := buildGateway(ctx, t, discoveryConfig(tt.agent), auditLog)

			list, err := agent.ListTools(ctx, nil)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			got := make([]string, 0, len(list.Tools))
			for _, tool := range list.Tools {
				got = append(got, tool.Name)
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.wantVisible) {
				t.Fatalf("tools visíveis = %v, quer %v", got, tt.wantVisible)
			}

			if tt.hiddenCall == "" {
				return
			}
			// Invisível NÃO basta: a tool oculta também tem de ser rejeitada se
			// chamada direto (a garantia do E3 depende do gate do E2).
			if _, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: tt.hiddenCall, Arguments: map[string]any{}}); err == nil {
				t.Fatalf("chamar tool oculta %q deveria falhar", tt.hiddenCall)
			} else if !strings.Contains(err.Error(), "acesso negado") {
				t.Fatalf("tool oculta %q: erro %q não parece deny de política", tt.hiddenCall, err)
			}
		})
	}
}
