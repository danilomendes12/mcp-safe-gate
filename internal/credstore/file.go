package credstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// keyLen é o tamanho da chave AES-256 (32 bytes).
const keyLen = 32

// envelope é o formato em disco do vault cifrado. O mapa de credenciais inteiro é
// serializado em JSON e cifrado com AES-256-GCM; só o nonce e o ciphertext (mais
// um marcador de versão) ficam em claro. GCM dá confidencialidade E integridade:
// adulterar o arquivo faz Open falhar, não devolver lixo silenciosamente.
type envelope struct {
	Version int    `json:"version"`
	Nonce   string `json:"nonce"`  // base64
	Cipher  string `json:"cipher"` // base64
}

// FileStore é o vault Tier 0 embarcado: um arquivo cifrado em repouso
// (AES-256-GCM), puro-Go (sem CGO ⇒ mantém CGO_ENABLED=0 + distroless). A chave
// vem de fora (env), nunca do arquivo. Cada operação carrega/regrava o arquivo
// inteiro — o volume de credenciais por gateway é pequeno, então isto é simples
// e correto antes de ser rápido.
type FileStore struct {
	path string
	gcm  cipher.AEAD
	mu   sync.Mutex
}

// DecodeKey decodifica a chave AES-256 em base64 (padrão) e valida o tamanho.
func DecodeKey(b64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("chave base64 inválida: %w", err)
	}
	if len(key) != keyLen {
		return nil, fmt.Errorf("chave precisa de %d bytes (AES-256), tem %d", keyLen, len(key))
	}
	return key, nil
}

// NewFileStore abre (ou prepara) o vault cifrado em path com a chave dada. Não
// exige que o arquivo exista ainda — um arquivo ausente é um vault vazio, e a
// primeira gravação o cria.
func NewFileStore(path string, key []byte) (*FileStore, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cifra: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &FileStore{path: path, gcm: gcm}, nil
}

// Lookup implementa Store. Ausente => ErrNoCredential (fail-closed).
func (f *FileStore) Lookup(_ context.Context, principal, upstream string) (Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	creds, err := f.load()
	if err != nil {
		return Credential{}, err
	}
	bearer, ok := creds[entryKey(upstream, principal)]
	if !ok {
		return Credential{}, ErrNoCredential
	}
	return Credential{Ref: ref(CredStoreFileScheme, upstream, principal), Bearer: bearer}, nil
}

// Put grava (ou substitui) a credencial de (principal, upstream) e persiste o
// vault cifrado, com permissões restritas (0600).
func (f *FileStore) Put(upstream, principal, bearer string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	creds, err := f.load()
	if err != nil {
		return err
	}
	creds[entryKey(upstream, principal)] = bearer
	return f.save(creds)
}

// List devolve os pares (upstream, principal) presentes — sem segredo.
func (f *FileStore) List() ([]Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	creds, err := f.load()
	if err != nil {
		return nil, err
	}
	return entriesOf(creds), nil
}

// CredStoreFileScheme é o prefixo do Ref de auditoria das credenciais de arquivo.
const CredStoreFileScheme = "file"

// load lê e decifra o vault. Arquivo ausente => mapa vazio (vault novo).
func (f *FileStore) load() (map[string]string, error) {
	raw, err := os.ReadFile(f.path) //nolint:gosec // path vem da config do operador
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lendo vault %q: %w", f.path, err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("vault %q corrompido: %w", f.path, err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("vault %q: nonce inválido: %w", f.path, err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.Cipher)
	if err != nil {
		return nil, fmt.Errorf("vault %q: cipher inválido: %w", f.path, err)
	}
	plain, err := f.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		// Chave errada OU arquivo adulterado: fail-closed, não devolve nada.
		return nil, fmt.Errorf("vault %q: falha ao decifrar (chave errada ou arquivo adulterado): %w", f.path, err)
	}
	var creds map[string]string
	if err := json.Unmarshal(plain, &creds); err != nil {
		return nil, fmt.Errorf("vault %q: payload inválido: %w", f.path, err)
	}
	return creds, nil
}

// save cifra e grava o vault atomicamente (escreve num temporário e renomeia).
func (f *FileStore) save(creds map[string]string) error {
	plain, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("serializando vault: %w", err)
	}
	nonce := make([]byte, f.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	ct := f.gcm.Seal(nil, nonce, plain, nil)
	out, err := json.Marshal(envelope{
		Version: 1,
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Cipher:  base64.StdEncoding.EncodeToString(ct),
	})
	if err != nil {
		return fmt.Errorf("serializando envelope: %w", err)
	}

	if dir := filepath.Dir(f.path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("criando dir do vault: %w", err)
		}
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("gravando vault: %w", err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		return fmt.Errorf("publicando vault: %w", err)
	}
	return nil
}
