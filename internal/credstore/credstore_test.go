package credstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return key
}

func TestMemoryStoreLookupAndFailClosed(t *testing.T) {
	s := NewMemoryStore("mem")
	s.Put("github", "alice", "alice-pat")

	got, err := s.Lookup(context.Background(), "alice", "github")
	if err != nil {
		t.Fatalf("lookup alice: %v", err)
	}
	if got.Bearer != "alice-pat" {
		t.Errorf("bearer = %q, quer alice-pat", got.Bearer)
	}
	if got.Ref != "mem:github/alice" {
		t.Errorf("ref = %q, quer mem:github/alice", got.Ref)
	}

	// Fail-closed: principal sem credencial NUNCA cai na de outro usuário.
	if _, err := s.Lookup(context.Background(), "bob", "github"); !errors.Is(err, ErrNoCredential) {
		t.Errorf("bob: erro = %v, quer ErrNoCredential", err)
	}
}

func TestFileStoreRoundTripAndEncryptionAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.enc")
	key := testKey(t)
	store, err := NewFileStore(path, key)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	const secret = "ghp_supersecretvalue123"
	if err := store.Put("github", "alice", secret); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Cifrado em repouso: o segredo NÃO pode aparecer em claro no arquivo.
	raw, err := os.ReadFile(path) //nolint:gosec // path é um tempdir de teste
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("segredo apareceu em claro no vault — cifra falhou")
	}
	if bytes.Contains(raw, []byte("alice")) {
		t.Fatal("principal apareceu em claro no vault (payload deveria estar cifrado)")
	}

	// Reabrir com a mesma chave decifra e devolve o segredo.
	reopened, err := NewFileStore(path, key)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := reopened.Lookup(context.Background(), "alice", "github")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.Bearer != secret {
		t.Errorf("bearer = %q, quer %q", got.Bearer, secret)
	}
	if got.Ref != "file:github/alice" {
		t.Errorf("ref = %q, quer file:github/alice", got.Ref)
	}
}

func TestFileStoreWrongKeyFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.enc")
	store, err := NewFileStore(path, testKey(t))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if err := store.Put("github", "alice", "secret"); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Chave errada: decifrar falha (GCM rejeita) — nunca devolve credencial.
	wrong, err := NewFileStore(path, testKey(t))
	if err != nil {
		t.Fatalf("NewFileStore wrong: %v", err)
	}
	if _, err := wrong.Lookup(context.Background(), "alice", "github"); err == nil {
		t.Fatal("lookup com chave errada deveria falhar")
	} else if errors.Is(err, ErrNoCredential) {
		t.Fatalf("erro deveria ser de decifra, não ErrNoCredential: %v", err)
	}
}

func TestFileStoreListNoSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.enc")
	store, err := NewFileStore(path, testKey(t))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	_ = store.Put("github", "bob", "x")
	_ = store.Put("github", "alice", "y")
	_ = store.Put("jira", "alice", "z")

	entries, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("esperava 3 entries, got %d", len(entries))
	}
	// Ordenado por (upstream, principal).
	want := []Entry{{"github", "alice"}, {"github", "bob"}, {"jira", "alice"}}
	for i, e := range entries {
		if e != want[i] {
			t.Errorf("entry[%d] = %+v, quer %+v", i, e, want[i])
		}
	}
}

func TestDecodeKeyValidation(t *testing.T) {
	if _, err := DecodeKey("not-base64!!!"); err == nil {
		t.Error("base64 inválido deveria falhar")
	}
	if _, err := DecodeKey("c2hvcnQ="); err == nil { // "short" decodifica mas tem < 32 bytes
		t.Error("chave curta deveria falhar")
	}
}
