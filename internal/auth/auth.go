// Package auth é o estágio 1 do gateway: autentica o cliente MCP e resolve a
// identidade do humano por trás do agente (o "principal").
//
// No E2 ainda NÃO há autenticação real. O que existe é o seam: um Resolver
// provisório devolve um principal fixo (o default_agent da config, ou
// "anonymous"), e o principal trafega pelo context.Context. Os estágios de
// admissão e RBAC (rate limit e política) leem o principal do context, nunca
// resolvem identidade eles mesmos.
//
// O E4 substitui APENAS o Resolver por um que extrai a identidade real
// (OAuth/JWT/bearer) — sem tocar em quem consome o principal.
package auth

import "context"

// Anonymous é o principal usado quando não há identidade configurada nem
// resolvida. Casa com o valor histórico do campo `identity` da auditoria.
const Anonymous = "anonymous"

// principalKey é a chave (não-exportada, para evitar colisão) sob a qual o
// principal é guardado no context.
type principalKey struct{}

// WithPrincipal devolve um context derivado carregando o principal.
func WithPrincipal(ctx context.Context, principal string) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}

// PrincipalFromContext extrai o principal do context. Se ausente ou vazio,
// devolve Anonymous — o pipeline nunca opera sem um principal.
func PrincipalFromContext(ctx context.Context) string {
	if p, ok := ctx.Value(principalKey{}).(string); ok && p != "" {
		return p
	}
	return Anonymous
}

// Resolver resolve o principal de uma requisição. É o ponto de extensão do E4.
type Resolver interface {
	Resolve(ctx context.Context) string
}

// StaticResolver é o Resolver provisório do E2: devolve sempre o mesmo
// principal (o default_agent da config). Não inspeciona a requisição — é só o
// suficiente para o RBAC já poder expressar regras por agente.
type StaticResolver struct {
	principal string
}

// NewStaticResolver cria um StaticResolver. defaultAgent vazio => Anonymous.
func NewStaticResolver(defaultAgent string) *StaticResolver {
	if defaultAgent == "" {
		defaultAgent = Anonymous
	}
	return &StaticResolver{principal: defaultAgent}
}

// Resolve devolve o principal fixo configurado, ignorando o context (E2).
func (r *StaticResolver) Resolve(context.Context) string { return r.principal }
