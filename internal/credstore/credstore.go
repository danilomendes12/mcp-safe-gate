// Package credstore é o vault de credenciais do leg SUL (E4-sul): resolve, a
// partir de (principal, upstream), a credencial com que o gateway chama um
// upstream que age POR CONTA do usuário (delegated / on-behalf-of).
//
// É o coração da defesa contra confused deputy (SAFE-T1307) e token scope
// substitution (SAFE-T1308): em vez de uma credencial compartilhada (qualquer
// agente passa a agir na conta do gateway) ou de repassar cegamente o token do
// norte ao upstream (token passthrough, proibido pela spec de auth do MCP), o
// gateway mapeia o principal verificado no norte → a credencial DAQUELE usuário,
// com fail-closed (sem credencial ⇒ negado) e auditoria identity-aware.
//
// A interface Store é plugável: o Tier 0 embarcado é um arquivo cifrado em
// repouso (AES-256-GCM, puro-Go, sem CGO — ver file.go); a mesma interface
// acomoda Vault/KMS no Tier 1 sem tocar no pipeline.
package credstore

import (
	"context"
	"errors"
)

// ErrNoCredential é o erro sentinela de fail-closed: não há credencial sul para
// o par (principal, upstream). O pipeline o traduz num erro JSON-RPC limpo e
// NUNCA cai numa credencial de outro usuário nem na conta de serviço por engano.
var ErrNoCredential = errors.New("nenhuma credencial sul para o (principal, upstream)")

// Credential é a credencial sul resolvida para um (principal, upstream).
//
// Ref é um identificador NÃO-SECRETO usado na auditoria (liga o humano do norte
// à ação no upstream sem vazar o segredo). Bearer é o segredo injetado no leg sul
// — nunca é logado nem exposto ao agente.
type Credential struct {
	Ref    string
	Bearer string
}

// Store resolve a credencial sul de cada (principal, upstream). Implementações
// devem ser seguras para uso concorrente.
type Store interface {
	// Lookup devolve a credencial de (principal, upstream) ou ErrNoCredential se
	// não houver — nunca uma credencial de fallback de outro principal.
	Lookup(ctx context.Context, principal, upstream string) (Credential, error)
}

// credKey é a chave (não-exportada) sob a qual a credencial sul resolvida viaja
// no context, do middleware de admissão sul (que faz o lookup e o fail-closed)
// até o RoundTripper que a injeta na request ao upstream.
type credKey struct{}

// WithCredential anexa a credencial sul resolvida ao context.
func WithCredential(ctx context.Context, c Credential) context.Context {
	return context.WithValue(ctx, credKey{}, c)
}

// FromContext recupera a credencial sul resolvida do context, se houver. O
// segundo retorno é false no caminho de boot (descoberta), quando nenhuma
// credencial por usuário foi resolvida.
func FromContext(ctx context.Context) (Credential, bool) {
	c, ok := ctx.Value(credKey{}).(Credential)
	return c, ok
}
