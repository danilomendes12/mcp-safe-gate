// Package auth é o estágio 1 do gateway: autentica o cliente MCP e resolve a
// identidade do humano por trás do agente (o "principal").
//
// Dois caminhos de resolução de principal, ambos terminando no context.Context
// (de onde os estágios de admissão e RBAC o leem — eles nunca resolvem
// identidade por conta própria):
//
//   - HTTP (E4): o bearer token é verificado pelo middleware RequireBearerToken
//     do SDK usando o TokenVerifier de NewVerifier (apikey/JWT). O principal sai
//     do TokenInfo resultante (ver PrincipalFromTokenInfo).
//   - stdio (caso laptop/single-user): não há bearer; o StaticResolver devolve o
//     default_agent da config (ou "anonymous"). Mesmo seam, sem auth.
//
// OAuth completo (oauthex, client-side) fica para fase posterior, como o E4 prevê.
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
