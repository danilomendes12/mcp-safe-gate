package proxy

// serve.go — transporte NORTE (voltado ao agente). O mesmo *mcp.Server roda em
// qualquer transporte; aqui só montamos a "porta de entrada": stdio (caso
// laptop/single-user, sem auth) ou Streamable HTTP servido por net/http (com a
// auth do E4 quando configurada). O leg sul (upstreams) é indiferente a isto.

import (
	"context"
	"errors"
	"net/http"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/danilomendes/mcpgate/internal/auth"
)

// httpShutdownTimeout limita o tempo de drenagem do servidor HTTP no shutdown
// gracioso (ctx cancelado por SIGINT/SIGTERM).
const httpShutdownTimeout = 5 * time.Second

// RunStdio sobe o servidor do gateway no transporte stdio. Bloqueia até a
// desconexão do agente ou o cancelamento do contexto. Útil em cenário
// laptop/single-user; o leg sul (upstreams) é indiferente a esta escolha.
func (p *Proxy) RunStdio(ctx context.Context) error {
	p.auditLog.Slog().Info("gateway ouvindo", "transport", "stdio")
	return p.server.Run(ctx, &mcp.StdioTransport{})
}

// RunHTTP sobe o servidor do gateway no transporte Streamable HTTP, servido por
// net/http em addr. Bloqueia até o cancelamento do contexto (SIGINT/SIGTERM),
// quando drena as conexões com shutdown gracioso.
//
// Usa os defaults do SDK: sem EventStore, sem modo stateless, sem sessões
// persistentes (E4/E10/E11). O mesmo *mcp.Server é devolvido a cada request —
// as sessões dos upstreams, abertas no boot, são compartilhadas por todos.
func (p *Proxy) RunHTTP(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           p.httpHandler(),
		ReadHeaderTimeout: 10 * time.Second, // mitiga slowloris (Slowloris/DoS)
	}

	// Shutdown gracioso: quando o ctx é cancelado, drena as conexões em vez de
	// derrubá-las no meio. ListenAndServe então retorna http.ErrServerClosed.
	// context.Background() abaixo é proposital: o ctx de request já está cancelado
	// (foi o que disparou o shutdown); a drenagem precisa do seu próprio prazo.
	go func() { //nolint:gosec // G118: shutdown context deve ser independente do ctx já cancelado
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	p.auditLog.Slog().Info("gateway ouvindo", "transport", "http", "addr", addr, "auth", p.cfg.Auth.Mode)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// httpHandler monta o handler Streamable HTTP do gateway e, quando há auth
// configurada (E4), o envolve com o middleware RequireBearerToken do SDK. Sem
// auth (mode none) devolve o handler cru — o caminho HTTP segue anônimo.
//
// É o ponto único que serve o caminho HTTP, compartilhado por RunHTTP e pelos
// testes de integração. O callback getServer devolve sempre o mesmo *mcp.Server.
func (p *Proxy) httpHandler() http.Handler {
	var handler http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return p.server
	}, nil)
	if p.verifier != nil {
		handler = sdkauth.RequireBearerToken(p.verifier, p.authOpts)(handler)
	}

	// Protected Resource Metadata (RFC 9728): se configurado, serve o metadata
	// num caminho dedicado (público, fora da auth) para o cliente descobrir o
	// authorization server a partir do WWW-Authenticate. Sem metadata, o handler
	// MCP cru responde a tudo (compat).
	if meta := auth.MetadataHandler(p.cfg.Auth); meta != nil {
		mux := http.NewServeMux()
		mux.Handle(auth.ProtectedResourceMetadataPath, meta)
		mux.Handle("/", handler)
		return mux
	}
	return handler
}
