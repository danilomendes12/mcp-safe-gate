package credstore

import (
	"context"
	"sort"
	"sync"
)

// Entry é um par (upstream, principal) presente no store — sem o segredo. Usado
// na listagem (`mcpgate cred ls`) e nos testes.
type Entry struct {
	Upstream  string
	Principal string
}

// entryKey monta a chave composta interna. O NUL separa os campos para evitar
// colisão entre nomes que se concatenariam de forma ambígua.
func entryKey(upstream, principal string) string {
	return upstream + "\x00" + principal
}

// MemoryStore é um Store em memória. Serve aos testes e é a base do FileStore
// (que persiste/cifra este mesmo mapa). O Ref devolvido é "<scheme>:<upstream>/
// <principal>" — identidade pura, sem segredo.
type MemoryStore struct {
	scheme string
	mu     sync.RWMutex
	creds  map[string]string // entryKey -> bearer
}

// NewMemoryStore cria um MemoryStore vazio. scheme prefixa o Ref de auditoria
// (ex.: "mem", "file").
func NewMemoryStore(scheme string) *MemoryStore {
	if scheme == "" {
		scheme = "mem"
	}
	return &MemoryStore{scheme: scheme, creds: map[string]string{}}
}

// Put grava (ou substitui) a credencial de (principal, upstream).
func (m *MemoryStore) Put(upstream, principal, bearer string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creds[entryKey(upstream, principal)] = bearer
}

// Lookup implementa Store. Ausente => ErrNoCredential (fail-closed).
func (m *MemoryStore) Lookup(_ context.Context, principal, upstream string) (Credential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	bearer, ok := m.creds[entryKey(upstream, principal)]
	if !ok {
		return Credential{}, ErrNoCredential
	}
	return Credential{Ref: ref(m.scheme, upstream, principal), Bearer: bearer}, nil
}

// List devolve os pares (upstream, principal) presentes, ordenados — sem segredo.
func (m *MemoryStore) List() []Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return entriesOf(m.creds)
}

// ref monta o identificador não-secreto de auditoria.
func ref(scheme, upstream, principal string) string {
	return scheme + ":" + upstream + "/" + principal
}

// entriesOf decompõe as chaves compostas em Entry, ordenadas de forma estável.
func entriesOf(creds map[string]string) []Entry {
	out := make([]Entry, 0, len(creds))
	for k := range creds {
		up, pr, _ := splitKey(k)
		out = append(out, Entry{Upstream: up, Principal: pr})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Upstream != out[j].Upstream {
			return out[i].Upstream < out[j].Upstream
		}
		return out[i].Principal < out[j].Principal
	})
	return out
}

// splitKey desfaz entryKey.
func splitKey(k string) (upstream, principal string, ok bool) {
	for i := 0; i < len(k); i++ {
		if k[i] == 0 {
			return k[:i], k[i+1:], true
		}
	}
	return k, "", false
}
