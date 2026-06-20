// Package audit emite o log estruturado de auditoria do gateway.
//
// Cada chamada de ferramenta (tools/call) que atravessa o proxy gera uma linha
// JSONL com os campos de Record. O sink é configurável (stdout ou arquivo).
// O campo `identity` já existe no schema (valor "anonymous" no MVP, já que não
// há autenticação ainda): é o diferencial identity-aware do produto e o schema
// do log não pode quebrar quando o estágio de identidade (E4) chegar.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/danilomendes/mcpgate/internal/config"
)

// Logger envolve um *slog.Logger configurado com handler JSON e expõe a
// emissão tipada de registros de auditoria.
type Logger struct {
	log    *slog.Logger
	closer io.Closer // não-nil quando o sink é um arquivo que precisamos fechar
}

// Record é o registro de auditoria de uma única chamada de ferramenta.
//
// Deliberadamente NÃO inclui os valores dos argumentos — apenas as chaves
// (ArgKeys) — para não vazar PII no log no MVP (a redação fica no estágio E5).
type Record struct {
	RequestID  string   // id curto, único por chamada
	Upstream   string   // nome do upstream que atendeu (ou seria roteado) a chamada
	Tool       string   // nome namespaced da tool (ex.: github.list_issues)
	Identity   string   // principal por trás do agente (resolvido no estágio de auth)
	Decision   string   // decisão de política: "allow" | "deny"
	ArgKeys    []string // apenas as chaves dos argumentos, nunca os valores
	DurationMS int64    // latência da chamada ao upstream (0 quando negada antes do forward)
	OK         bool     // true se a chamada teve sucesso a nível de transporte
	Error      string   // mensagem de erro / motivo do deny (vazio se OK e allow)
}

// IdentityAnonymous é o principal usado enquanto o estágio de auth (E4) não
// resolve identidade real. Mantida como constante para o dia em que houver.
const IdentityAnonymous = "anonymous"

// Decisões de política registradas no campo `decision` da auditoria.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// New constrói um Logger a partir da config de auditoria. Quando o sink é um
// arquivo, o caller deve chamar Close para liberar o descritor.
func New(cfg config.Audit) (*Logger, error) {
	var w io.Writer
	var closer io.Closer

	switch cfg.Sink {
	case config.SinkFile:
		f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("abrindo arquivo de auditoria %q: %w", cfg.Path, err)
		}
		w, closer = f, f
	default: // SinkStdout (já validado em config)
		w = os.Stdout
	}

	// slog.NewJSONHandler já emite uma linha JSON por registro: é o nosso JSONL.
	// ReplaceAttr renomeia a chave de tempo padrão (`time`) para `ts` e a fixa
	// em RFC3339, conforme o schema do registro de auditoria.
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Key = "ts"
				if t, ok := a.Value.Any().(time.Time); ok {
					a.Value = slog.StringValue(t.Format(time.RFC3339))
				}
			}
			return a
		},
	}
	handler := slog.NewJSONHandler(w, opts)
	return &Logger{log: slog.New(handler), closer: closer}, nil
}

// Slog expõe o *slog.Logger subjacente para mensagens operacionais (warns,
// boot, etc.) que devem compartilhar o mesmo sink/handler da auditoria.
func (l *Logger) Slog() *slog.Logger { return l.log }

// Emit escreve uma linha de auditoria. O timestamp (`ts`) é adicionado pelo
// handler do slog automaticamente.
func (l *Logger) Emit(r Record) {
	l.log.Info("tool_call",
		slog.String("request_id", r.RequestID),
		slog.String("upstream", r.Upstream),
		slog.String("tool", r.Tool),
		slog.String("identity", r.Identity),
		slog.String("decision", r.Decision),
		slog.Any("arg_keys", r.ArgKeys),
		slog.Int64("duration_ms", r.DurationMS),
		slog.Bool("ok", r.OK),
		slog.String("error", r.Error),
	)
}

// Close libera o sink quando ele é um arquivo. No-op para stdout.
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// NewRequestID gera um id curto (8 bytes / 16 hex) para correlacionar uma
// chamada nos logs. Em caso de falha do RNG, cai para o timestamp em nanos.
func NewRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("ts-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
