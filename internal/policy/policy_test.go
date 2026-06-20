package policy_test

import (
	"testing"

	"github.com/danilomendes/mcpgate/internal/config"
	"github.com/danilomendes/mcpgate/internal/policy"
)

func TestEvaluate(t *testing.T) {
	cfg := config.Policy{
		Default:    config.PolicyDeny,
		AllowTools: []string{"everything.echo", "everything.add"},
		DenyTools:  []string{"everything.add"}, // deny precede allow (mesma tool)
	}
	e := policy.NewEngine(cfg)

	tests := []struct {
		name       string
		tool       string
		wantAllow  bool
		wantReason string
	}{
		{"allow casa", "everything.echo", true, "allow_tools"},
		{"deny vence allow", "everything.add", false, "deny_tools"},
		{"default deny", "everything.printEnv", false, "default_deny"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := e.Evaluate("anonymous", tt.tool)
			if d.Allow != tt.wantAllow {
				t.Fatalf("Allow = %v, quer %v", d.Allow, tt.wantAllow)
			}
			if d.Reason != tt.wantReason {
				t.Errorf("Reason = %q, quer %q", d.Reason, tt.wantReason)
			}
		})
	}
}

func TestEvaluateDefaultAllow(t *testing.T) {
	e := policy.NewEngine(config.Policy{
		Default:   config.PolicyAllow,
		DenyTools: []string{"everything.add"},
	})
	if d := e.Evaluate("x", "everything.echo"); !d.Allow || d.Reason != "default_allow" {
		t.Fatalf("esperava default_allow, got %+v", d)
	}
	if d := e.Evaluate("x", "everything.add"); d.Allow {
		t.Fatalf("deny_tools deveria barrar mesmo com default allow, got %+v", d)
	}
}

func TestEvaluateEmptyDefaultIsDeny(t *testing.T) {
	// Default vazio => postura default-deny (segurança).
	e := policy.NewEngine(config.Policy{})
	if d := e.Evaluate("x", "everything.echo"); d.Allow || d.Reason != "default_deny" {
		t.Fatalf("default vazio deveria negar, got %+v", d)
	}
}

func TestEvaluatePerAgentOverride(t *testing.T) {
	e := policy.NewEngine(config.Policy{
		Default:    config.PolicyDeny,
		AllowTools: []string{"everything.echo"},
		Agents: map[string]config.AgentPolicy{
			"ci-bot": {Default: config.PolicyAllow, DenyTools: []string{"everything.echo"}},
		},
	})

	// Agente sem override usa as regras globais.
	if d := e.Evaluate("anonymous", "everything.echo"); !d.Allow {
		t.Errorf("global: echo deveria ser permitido, got %+v", d)
	}
	// ci-bot usa o próprio ruleset: default allow, mas deny do echo vence.
	if d := e.Evaluate("ci-bot", "everything.echo"); d.Allow {
		t.Errorf("ci-bot: deny_tools deveria barrar echo, got %+v", d)
	}
	if d := e.Evaluate("ci-bot", "everything.printEnv"); !d.Allow {
		t.Errorf("ci-bot: default allow deveria permitir printEnv, got %+v", d)
	}
}
