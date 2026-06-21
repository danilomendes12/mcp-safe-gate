package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/danilomendes/mcpgate/internal/config"
)

// apiKeyAuthConfig: mode=apikey, scope obrigatório "tools:call". alice tem o
// scope e enxerga só everything.echo; bob não tem o scope (=> 403).
func apiKeyAuthConfig() *config.Config {
	return &config.Config{
		Policy: config.Policy{
			Default: config.PolicyDeny,
			Agents: map[string]config.AgentPolicy{
				"alice": {AllowTools: []string{"everything.echo"}},
			},
		},
		Auth: config.Auth{
			Mode:                config.AuthAPIKey,
			RequiredScopes:      []string{"tools:call"},
			ResourceMetadataURL: "https://example.test/.well-known/oauth-protected-resource",
			APIKeys: []config.APIKey{
				{Key: "alice-key", Principal: "alice", Scopes: []string{"tools:call"}},
				{Key: "noscope-key", Principal: "bob"},
			},
		},
	}
}

// postAuth manda um POST mínimo ao endpoint com o bearer dado (vazio = sem
// header). Os casos negativos são barrados pelo middleware ANTES do handler MCP,
// então o corpo não precisa ser um handshake válido.
func postAuth(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// TestHTTPAuthRejections cobre o caminho HTTP do E4: sem token, token inválido e
// scope insuficiente. Todos com status correto e WWW-Authenticate onde aplicável.
func TestHTTPAuthRejections(t *testing.T) {
	ctx := context.Background()
	auditLog := newAudit(t, filepath.Join(t.TempDir(), "audit.jsonl"))
	p := buildProxy(ctx, t, apiKeyAuthConfig(), auditLog)
	ts := httptest.NewServer(p.httpHandler())
	t.Cleanup(ts.Close)

	t.Run("sem token => 401 + WWW-Authenticate", func(t *testing.T) {
		resp := postAuth(t, ts.URL, "")
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, quer 401", resp.StatusCode)
		}
		if wa := resp.Header.Get("WWW-Authenticate"); !strings.Contains(wa, "Bearer") {
			t.Fatalf("WWW-Authenticate = %q, quer conter Bearer", wa)
		}
	})

	t.Run("token desconhecido => 401", func(t *testing.T) {
		resp := postAuth(t, ts.URL, "nao-existe")
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, quer 401", resp.StatusCode)
		}
	})

	t.Run("scope insuficiente => 403", func(t *testing.T) {
		resp := postAuth(t, ts.URL, "noscope-key")
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, quer 403", resp.StatusCode)
		}
		if wa := resp.Header.Get("WWW-Authenticate"); !strings.Contains(wa, "scope") {
			t.Fatalf("WWW-Authenticate = %q, quer conter scope", wa)
		}
	})
}

// TestHTTPAuthValidTokenFiltersDiscovery prova o caminho feliz ponta a ponta: um
// cliente MCP real sobre HTTP com bearer válido autentica, e o tools/list já vem
// filtrado pela identidade resolvida do token (alice só vê everything.echo).
func TestHTTPAuthValidTokenFiltersDiscovery(t *testing.T) {
	ctx := context.Background()
	auditLog := newAudit(t, filepath.Join(t.TempDir(), "audit.jsonl"))
	p := buildProxy(ctx, t, apiKeyAuthConfig(), auditLog)
	ts := httptest.NewServer(p.httpHandler())
	t.Cleanup(ts.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "test"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:   ts.URL,
		HTTPClient: &http.Client{Transport: bearerRoundTripper{token: "alice-key", next: http.DefaultTransport}},
	}
	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect com token válido: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	list, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Tools) != 1 || list.Tools[0].Name != "everything.echo" {
		t.Fatalf("tools visíveis = %+v, quer só everything.echo", list.Tools)
	}
}

// TestHTTPAuthExpiredJWT prova que um JWT expirado é rejeitado com 401 pelo
// middleware (que checa exp a partir do TokenInfo.Expiration que preenchemos).
func TestHTTPAuthExpiredJWT(t *testing.T) {
	ctx := context.Background()
	auditLog := newAudit(t, filepath.Join(t.TempDir(), "audit.jsonl"))
	const secret = "segredo-teste" //nolint:gosec // G101: segredo de teste, não é credencial real
	cfg := &config.Config{
		Policy: config.Policy{Default: config.PolicyDeny},
		Auth:   config.Auth{Mode: config.AuthJWT, JWT: config.JWT{Secret: secret}},
	}
	p := buildProxy(ctx, t, cfg, auditLog)
	ts := httptest.NewServer(p.httpHandler())
	t.Cleanup(ts.Close)

	expired := signJWT(t, secret, map[string]any{"sub": "alice", "exp": float64(time.Now().Add(-time.Hour).Unix())})
	resp := postAuth(t, ts.URL, expired)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, quer 401 (token expirado)", resp.StatusCode)
	}
}

// signJWT monta um JWT HS256 válido (assinatura correta) com as claims dadas.
func signJWT(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(map[string]any{"alg": "HS256", "typ": "JWT"}) + "." + enc(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
