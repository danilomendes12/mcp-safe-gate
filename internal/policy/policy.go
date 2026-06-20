// Package policy é o estágio 2 do gateway: RBAC por ferramenta com postura
// default-deny.
//
// O Engine avalia o par (principal, tool) e devolve uma Decision. A tool é o
// nome NAMESPACED visto pelo agente (ex.: "github.list_issues"). Precedência:
//
//  1. deny_tools casou  -> deny (deny vence allow)
//  2. allow_tools casou -> allow
//  3. nada casou        -> o default (deny|allow); default vazio => deny
//
// Se o principal tiver regras próprias em policy.agents, elas substituem as
// listas globais; senão valem as globais. Quem popula o principal é o resolver
// do pacote auth (provisório no E2, real no E4) — este pacote não conhece
// identidade, só consome o principal já resolvido.
//
// Filtrar tools/list (esconder a tool negada da descoberta) é E3: aqui a tool
// negada continua visível e é bloqueada apenas no tools/call.
package policy

import "github.com/danilomendes/mcpgate/internal/config"

// Decision é o resultado de uma avaliação de política.
type Decision struct {
	Allow  bool
	Reason string // curto, para auditoria e mensagem de erro (ex.: "deny_tools")
}

// ruleset é a forma compilada de um conjunto de regras (global ou por agente):
// listas viram sets para lookup O(1) e o default vira bool.
type ruleset struct {
	allow        map[string]struct{}
	deny         map[string]struct{}
	defaultAllow bool
}

// Engine avalia política. Construa com NewEngine e use de forma concorrente:
// após a construção é somente-leitura.
type Engine struct {
	global ruleset
	agents map[string]ruleset
}

// NewEngine compila a configuração de política num Engine.
func NewEngine(cfg config.Policy) *Engine {
	e := &Engine{
		global: compile(cfg.Default, cfg.AllowTools, cfg.DenyTools),
		agents: make(map[string]ruleset, len(cfg.Agents)),
	}
	for agent, ap := range cfg.Agents {
		e.agents[agent] = compile(ap.Default, ap.AllowTools, ap.DenyTools)
	}
	return e
}

// compile transforma listas + string de default num ruleset.
func compile(deflt string, allow, deny []string) ruleset {
	return ruleset{
		allow:        toSet(allow),
		deny:         toSet(deny),
		defaultAllow: deflt == config.PolicyAllow, // "", "deny" e qualquer outro => deny
	}
}

func toSet(items []string) map[string]struct{} {
	s := make(map[string]struct{}, len(items))
	for _, it := range items {
		s[it] = struct{}{}
	}
	return s
}

// Evaluate decide se o principal pode chamar a tool (nome namespaced).
func (e *Engine) Evaluate(principal, tool string) Decision {
	rs := e.global
	if ar, ok := e.agents[principal]; ok {
		rs = ar
	}

	if _, denied := rs.deny[tool]; denied {
		return Decision{Allow: false, Reason: "deny_tools"}
	}
	if _, allowed := rs.allow[tool]; allowed {
		return Decision{Allow: true, Reason: "allow_tools"}
	}
	if rs.defaultAllow {
		return Decision{Allow: true, Reason: "default_allow"}
	}
	return Decision{Allow: false, Reason: "default_deny"}
}
