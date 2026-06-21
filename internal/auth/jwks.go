// jwks.go — cliente JWKS para o modo OIDC (E4, leg norte). Busca as chaves
// públicas do IdP no `jwks_uri`, indexa por `kid`, cacheia com TTL e refaz o
// fetch quando aparece um `kid` desconhecido (rotação de chaves). Puro stdlib:
// crypto/rsa, math/big, base64url, encoding/json — sem lib de JWT.
//
// Por que cachear: o JWKS muda raramente (rotação), mas é consultado a cada
// token. Por que refazer no kid desconhecido: numa rotação, o IdP passa a
// assinar com uma chave nova ANTES de o cache expirar; sem o refetch sob demanda,
// tokens válidos seriam recusados. Um coolDown evita que tokens com kid forjado
// virem um vetor de DoS contra o IdP (refetch a cada token inválido).

package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Defaults do cache de JWKS.
const (
	defaultJWKSTTL      = 1 * time.Hour    // revalida o JWKS após este tempo
	defaultJWKSCoolDown = 1 * time.Minute  // intervalo mínimo entre refetches forçados
	jwksFetchTimeout    = 10 * time.Second // teto por requisição ao IdP
	jwksMaxBytes        = 1 << 20          // 1 MiB: limite defensivo do corpo do JWKS
)

// jwk é uma chave RSA pública no formato JWK (RFC 7517) — só os campos que usamos.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"` // módulo, base64url big-endian
	E   string `json:"e"` // expoente, base64url big-endian
}

// jwksDoc é o documento JWKS (RFC 7517 §5).
type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// oidcDiscovery é o subconjunto do OpenID Provider Metadata que consumimos.
type oidcDiscovery struct {
	JWKSURI string `json:"jwks_uri"`
}

// jwksCache resolve `kid` → *rsa.PublicKey com cache, TTL e rotação.
type jwksCache struct {
	jwksURI    string // explícito; se vazio, resolvido via discovery do issuer
	issuer     string
	httpClient *http.Client
	ttl        time.Duration
	coolDown   time.Duration

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

// newJWKSCache cria o cache com os defaults de produção.
func newJWKSCache(jwksURI, issuer string) *jwksCache {
	return &jwksCache{
		jwksURI:    jwksURI,
		issuer:     issuer,
		httpClient: &http.Client{Timeout: jwksFetchTimeout},
		ttl:        defaultJWKSTTL,
		coolDown:   defaultJWKSCoolDown,
	}
}

// key devolve a chave pública para o kid, buscando/atualizando o JWKS conforme
// necessário. É seguro para uso concorrente (serializa fetch sob o mutex).
func (c *jwksCache) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stale := c.keys == nil || time.Since(c.fetchedAt) > c.ttl
	if stale {
		if err := c.refresh(ctx); err != nil && c.keys == nil {
			return nil, err // sem cache anterior pra cair: propaga
		}
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	// kid desconhecido: pode ser rotação. Refaz o fetch, respeitando o coolDown
	// para não virar amplificador de DoS contra o IdP com kids forjados.
	if time.Since(c.lastAttempt) >= c.coolDown {
		if err := c.refresh(ctx); err != nil {
			return nil, err
		}
		if k, ok := c.keys[kid]; ok {
			return k, nil
		}
	}
	return nil, fmt.Errorf("kid %q não encontrado no JWKS", kid)
}

// refresh resolve o jwks_uri (discovery se necessário), baixa e indexa as chaves.
// Atualiza lastAttempt mesmo em falha, para o coolDown valer.
func (c *jwksCache) refresh(ctx context.Context) error {
	c.lastAttempt = time.Now()

	uri := c.jwksURI
	if uri == "" {
		discovered, err := c.discoverJWKSURI(ctx)
		if err != nil {
			return err
		}
		uri = discovered
	}

	doc, err := c.fetchJWKS(ctx, uri)
	if err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue // só chaves RSA de assinatura
		}
		pub, err := k.rsaPublicKey()
		if err != nil {
			continue // ignora chave malformada, não derruba o set inteiro
		}
		if k.Kid == "" {
			continue // sem kid não há como casar pelo header
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("JWKS %q não trouxe nenhuma chave RSA utilizável", uri)
	}
	c.keys = keys
	c.fetchedAt = time.Now()
	return nil
}

// discoverJWKSURI resolve o jwks_uri via <issuer>/.well-known/openid-configuration.
func (c *jwksCache) discoverJWKSURI(ctx context.Context) (string, error) {
	if c.issuer == "" {
		return "", fmt.Errorf("oidc: sem jwks_uri nem issuer para discovery")
	}
	disco := strings.TrimRight(c.issuer, "/") + "/.well-known/openid-configuration"
	if err := checkHTTPSOrLoopback(disco); err != nil {
		return "", err
	}
	var meta oidcDiscovery
	if err := c.getJSON(ctx, disco, &meta); err != nil {
		return "", fmt.Errorf("oidc discovery: %w", err)
	}
	if meta.JWKSURI == "" {
		return "", fmt.Errorf("oidc discovery: openid-configuration sem jwks_uri")
	}
	return meta.JWKSURI, nil
}

// fetchJWKS baixa e decodifica o documento JWKS.
func (c *jwksCache) fetchJWKS(ctx context.Context, uri string) (*jwksDoc, error) {
	if err := checkHTTPSOrLoopback(uri); err != nil {
		return nil, err
	}
	var doc jwksDoc
	if err := c.getJSON(ctx, uri, &doc); err != nil {
		return nil, fmt.Errorf("buscando JWKS %q: %w", uri, err)
	}
	return &doc, nil
}

// getJSON faz um GET e decodifica o corpo (limitado) em out.
func (c *jwksCache) getJSON(ctx context.Context, uri string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, jwksMaxBytes))
	return dec.Decode(out)
}

// rsaPublicKey reconstrói a chave RSA a partir dos campos n/e (base64url).
func (k jwk) rsaPublicKey() (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("modulo n inválido: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("expoente e inválido: %w", err)
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() < 2 {
		return nil, fmt.Errorf("expoente e fora do intervalo")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, nil
}

// checkHTTPSOrLoopback exige HTTPS, exceto para endereços de loopback (dev/teste).
// Evita buscar chaves de confiança por canal em claro contra um host remoto.
func checkHTTPSOrLoopback(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("url inválida %q: %w", raw, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("url %q precisa ser https (http só em loopback)", raw)
}

// isLoopbackHost reconhece localhost e o bloco de loopback.
func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasPrefix(host, "127.")
}
