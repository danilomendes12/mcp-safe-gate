// Package config carrega e valida a configuração do mcpgate (mcpgate.yaml).
//
// Cobre os upstreams, o RBAC por ferramenta (Policy, estágio 2), a quota de
// admissão por agente (RateLimit) e o sink de auditoria. Campos de estágios
// ainda por vir (ex.: identidade real do E4) entram no schema cedo, de
// propósito, para o formato do arquivo nascer estável.
package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// envPrefix é o prefixo das variáveis de ambiente que sobrescrevem a config.
// Ex.: MCPGATE_LISTEN=":9090" sobrescreve `listen`.
const envPrefix = "MCPGATE_"

// Transport enumera os transportes suportados para um upstream.
const (
	TransportStdio = "stdio"
	TransportHTTP  = "http"
)

// Sink enumera os destinos suportados para o log de auditoria.
const (
	SinkStdout = "stdout"
	SinkFile   = "file"
)

// Decisão default da política (campo `default` de policy/agents).
const (
	PolicyDeny  = "deny"
	PolicyAllow = "allow"
)

// Modos de autenticação do transporte norte (estágio 1 / E4). Só valem no
// caminho HTTP; em stdio a identidade é sempre "anonymous".
const (
	AuthNone   = "none"   // sem autenticação: principal cai no default_agent (compat E2)
	AuthAPIKey = "apikey" // bearer = API key estática mapeada a um principal
	AuthJWT    = "jwt"    // bearer = JWT HS256 assinado com segredo compartilhado
	AuthOIDC   = "oidc"   // bearer = JWT RS256 de um IdP externo, validado via JWKS
)

// Tipos de autenticação do transporte sul (gateway → upstream HTTP). Determinam
// COM QUAL credencial o gateway chama o upstream. Vazio + bearer_token preenchido
// => service_bearer (compat). Confundir conta de serviço com per_user é falha de
// segurança (SAFE-T1307, confused deputy) — ver docs/BACKLOG E4-sul.
const (
	SouthAuthServiceBearer  = "service_bearer"   // bearer estático único do gateway p/ o upstream
	SouthAuthServiceOAuthCC = "service_oauth_cc" // OAuth client-credentials (token que renova sozinho)
	SouthAuthPerUser        = "per_user"         // credencial DELEGADA: derivada do principal do norte
)

// Backends do vault de credenciais sul (per_user). file = arquivo cifrado em
// repouso (AES-256-GCM, puro-Go, sem CGO); a interface fica pronta p/ Vault/KMS.
const (
	CredStoreFile = "file"
)

// Config é a configuração completa do gateway.
type Config struct {
	// Listen é o endereço do transporte HTTP voltado ao agente (serve --transport http).
	Listen string `koanf:"listen"`
	// DefaultAgent é o principal provisório que o resolver de identidade devolve
	// enquanto não há autenticação real (E4 troca o resolver). Vazio => "anonymous".
	DefaultAgent string `koanf:"default_agent"`
	// Upstreams são os servidores MCP que o gateway fronteia.
	Upstreams []Upstream `koanf:"upstreams"`
	// Auth é a autenticação do cliente no transporte norte (estágio 1 / E4). Só
	// tem efeito no caminho HTTP; stdio é sempre "anonymous". Vazio => sem auth.
	Auth Auth `koanf:"auth"`
	// Policy é o RBAC por ferramenta (estágio 2 / E2): default-deny + allow/deny.
	Policy Policy `koanf:"policy"`
	// RateLimit é a admissão por agente (token bucket in-process). RPS<=0 desliga.
	RateLimit RateLimit `koanf:"rate_limit"`
	// Audit controla o sink/formato do log de auditoria.
	Audit Audit `koanf:"audit"`
	// Credentials é o vault de credenciais sul por (principal, upstream), usado
	// pelos upstreams com auth.type=per_user (E4-sul). Vazio quando nenhum
	// upstream é per_user.
	Credentials Credentials `koanf:"credentials"`
}

// Upstream descreve um servidor MCP upstream.
type Upstream struct {
	// Name é único e vira o prefixo de namespace das tools (ex.: `github`).
	Name string `koanf:"name"`
	// Transport é "stdio" ou "http".
	Transport string `koanf:"transport"`
	// Command é o argv do processo upstream; obrigatório se transport=stdio.
	Command []string `koanf:"command"`
	// URL é o endpoint MCP; obrigatório se transport=http.
	URL string `koanf:"url"`
	// BearerToken, se presente, é injetado como `Authorization: Bearer` em cada
	// requisição ao upstream (leg sul, transport=http). É o segredo que o gateway
	// usa para se autenticar no upstream — NUNCA é exposto ao agente. Aceita
	// override por ambiente (ex.: MCPGATE_UPSTREAMS_0_BEARER_TOKEN). Atalho
	// (compat) para auth.type=service_bearer com o segredo inline.
	BearerToken string `koanf:"bearer_token"`
	// Auth descreve COM QUAL credencial o gateway chama este upstream (leg sul /
	// E4-sul). Vazio + BearerToken preenchido => service_bearer.
	Auth UpstreamAuth `koanf:"auth"`
}

// UpstreamAuth descreve a credencial do leg SUL de um upstream (E4-sul): conta de
// serviço (uma credencial do gateway) OU delegada por usuário (derivada do
// principal do norte). Misturar os dois modelos é falha de segurança: uma
// credencial compartilhada num upstream que age por conta vira confused deputy
// (SAFE-T1307) e qualquer agente autenticado passa a agir na conta do gateway.
type UpstreamAuth struct {
	// Type é "service_bearer", "service_oauth_cc" ou "per_user". Vazio herda o
	// comportamento legado (service_bearer se BearerToken estiver preenchido).
	Type string `koanf:"type"`
	// BearerEnv é o nome da variável de ambiente com o bearer estático
	// (service_bearer). Mantém o segredo fora do YAML versionado.
	BearerEnv string `koanf:"bearer_env"`
	// OAuth configura o fluxo client-credentials (service_oauth_cc).
	OAuth UpstreamOAuthCC `koanf:"oauth"`
	// DiscoveryBearerEnv (per_user, opcional) é a env com o bearer usado APENAS
	// para conectar e listar tools no boot, quando o upstream exige auth até para
	// tools/list. As chamadas de tool (tools/call) usam SEMPRE a credencial do
	// usuário; este token de descoberta nunca é usado para agir por conta.
	DiscoveryBearerEnv string `koanf:"discovery_bearer_env"`
}

// UpstreamOAuthCC configura a conta de serviço via OAuth 2.0 client-credentials
// (RFC 6749 §4.4): o gateway obtém e renova sozinho um access token p/ o upstream.
type UpstreamOAuthCC struct {
	// TokenURL é o endpoint de token do authorization server.
	TokenURL string `koanf:"token_url"`
	// ClientIDEnv / ClientSecretEnv são as envs com as credenciais do client.
	ClientIDEnv     string `koanf:"client_id_env"`
	ClientSecretEnv string `koanf:"client_secret_env"`
	// Scopes solicitados ao authorization server (menor privilégio).
	Scopes []string `koanf:"scopes"`
}

// Credentials configura o vault de credenciais sul por (principal, upstream)
// usado pelos upstreams per_user (E4-sul). Tier 0 embarcado: arquivo cifrado em
// repouso; a interface (internal/credstore) fica pronta p/ Vault/KMS no Tier 1.
type Credentials struct {
	// Store é o backend: "file" (arquivo cifrado AES-256-GCM). Vazio => nenhum
	// vault configurado (só é exigido se houver upstream per_user).
	Store string `koanf:"store"`
	// File configura o backend de arquivo cifrado.
	File CredentialsFile `koanf:"file"`
}

// CredentialsFile aponta o arquivo cifrado e a fonte da chave de cifra.
type CredentialsFile struct {
	// Path é o arquivo cifrado (criado/atualizado pelo subcomando `mcpgate cred`).
	Path string `koanf:"path"`
	// KeyEnv é a env com a chave AES-256 em base64 (32 bytes). NUNCA versionada.
	KeyEnv string `koanf:"key_env"`
}

// Auth descreve a autenticação do cliente MCP no transporte norte (estágio 1).
// Mode seleciona o verificador do bearer token; RequiredScopes são os scopes
// exigidos em TODA requisição (o middleware do SDK os checa — não duplicamos).
type Auth struct {
	// Mode é "none" (default), "apikey" ou "jwt".
	Mode string `koanf:"mode"`
	// RequiredScopes são exigidos em toda requisição autenticada. Faltando =>
	// 403 + WWW-Authenticate.
	RequiredScopes []string `koanf:"required_scopes"`
	// ResourceMetadataURL é opcional: vai no header WWW-Authenticate para o fluxo
	// de protected resource metadata (RFC 9728).
	ResourceMetadataURL string `koanf:"resource_metadata_url"`
	// Resource é o identificador deste resource server (RFC 9728) — tipicamente a
	// URL pública do gateway. Vai no campo `resource` do Protected Resource
	// Metadata. Opcional; habilita o endpoint de metadata junto com ResourceMetadataURL.
	Resource string `koanf:"resource"`
	// APIKeys mapeia cada key estática a um principal (mode=apikey).
	APIKeys []APIKey `koanf:"api_keys"`
	// JWT configura a verificação de JWT HS256 (mode=jwt).
	JWT JWT `koanf:"jwt"`
	// OIDC configura a verificação de JWT RS256 de um IdP externo via JWKS (mode=oidc).
	OIDC OIDC `koanf:"oidc"`
}

// OIDC configura a validação de JWT RS256 emitido por um IdP externo (mode=oidc).
// As chaves públicas vêm do JWKS do IdP (jwks_uri), casadas pelo `kid` do header
// e cacheadas com rotação. A assinatura, `iss` e `aud` são checados aqui; exp e
// scopes ficam com o middleware do SDK (não duplicamos).
type OIDC struct {
	// Issuer é validado contra a claim `iss`. Se JWKSURI estiver vazio, o
	// jwks_uri é descoberto via <issuer>/.well-known/openid-configuration.
	Issuer string `koanf:"issuer"`
	// JWKSURI é a URL do JWKS do IdP. Opcional se Issuer permitir discovery.
	JWKSURI string `koanf:"jwks_uri"`
	// Audience, se setado, é validado contra a claim `aud`.
	Audience string `koanf:"audience"`
	// Algorithms são os algoritmos de assinatura aceitos. Vazio => ["RS256"].
	// Algoritmos não suportados (ex.: "none", "HS256") são recusados.
	Algorithms []string `koanf:"algorithms"`
	// PrincipalClaim é a claim usada como principal. Vazio => "sub".
	PrincipalClaim string `koanf:"principal_claim"`
}

// APIKey associa uma API key estática a um principal e a scopes opcionais.
type APIKey struct {
	// Key é o valor do bearer token apresentado pelo cliente.
	Key string `koanf:"key"`
	// Principal é o "humano por trás do agente" resolvido a partir desta key.
	Principal string `koanf:"principal"`
	// Scopes concedidos a esta key (casados contra Auth.RequiredScopes).
	Scopes []string `koanf:"scopes"`
}

// JWT configura a verificação de JWT assinado em HS256 (segredo compartilhado).
// RS256/JWKS e OAuth completo ficam para fase posterior (E4), como o backlog prevê.
type JWT struct {
	// Secret é o segredo compartilhado HS256. Obrigatório quando mode=jwt.
	Secret string `koanf:"secret"`
	// PrincipalClaim é a claim usada como principal. Vazio => "sub".
	PrincipalClaim string `koanf:"principal_claim"`
	// Issuer, se setado, é validado contra a claim `iss`.
	Issuer string `koanf:"issuer"`
	// Audience, se setado, é validado contra a claim `aud`.
	Audience string `koanf:"audience"`
}

// Policy é o RBAC por ferramenta. A avaliação é por tool NAMESPACED
// (ex.: "github.list_issues"): deny tem precedência sobre allow; o que não casa
// nenhuma lista cai no Default. Default vazio => deny (postura default-deny).
//
// Agents permite regras por principal: se o principal tiver entrada em Agents,
// ela substitui as listas globais; senão valem as globais. O principal é
// provisório no E2 (ver DefaultAgent); o E4 só troca o resolver de identidade.
type Policy struct {
	Default    string                 `koanf:"default"` // "deny" | "allow"
	AllowTools []string               `koanf:"allow_tools"`
	DenyTools  []string               `koanf:"deny_tools"`
	Agents     map[string]AgentPolicy `koanf:"agents"`
}

// AgentPolicy é o conjunto de regras de um principal específico.
type AgentPolicy struct {
	Default    string   `koanf:"default"` // "deny" | "allow"; vazio herda a postura default-deny
	AllowTools []string `koanf:"allow_tools"`
	DenyTools  []string `koanf:"deny_tools"`
}

// RateLimit é a quota de admissão por agente (token bucket puro-Go, in-process).
// Mapeia a defesa contra DoS por exaustão de recursos (SAFE-MCP / Impact,
// ATK-TA0040). RPS<=0 desliga o rate limiting.
type RateLimit struct {
	RPS   float64 `koanf:"rps"`   // tokens por segundo, por agente
	Burst int     `koanf:"burst"` // capacidade do bucket; >=1 quando RPS>0
}

// Audit controla o destino e o formato do log de auditoria.
type Audit struct {
	// Sink é "stdout" ou "file".
	Sink string `koanf:"sink"`
	// Format é o formato do log; no MVP apenas "jsonl".
	Format string `koanf:"format"`
	// Path é o arquivo de destino quando Sink == "file".
	Path string `koanf:"path"`
}

// Load lê o arquivo YAML em path, aplica overrides de ambiente (prefixo
// MCPGATE_) e valida estaticamente o resultado.
func Load(path string) (*Config, error) {
	k := koanf.New(".")

	if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("carregando config %q: %w", path, err)
	}

	// Overrides de ambiente: MCPGATE_AUDIT_SINK -> audit.sink, etc.
	envCb := func(s string) string {
		s = strings.TrimPrefix(s, envPrefix)
		return strings.ReplaceAll(strings.ToLower(s), "_", ".")
	}
	if err := k.Load(env.Provider(envPrefix, ".", envCb), nil); err != nil {
		return nil, fmt.Errorf("carregando env (%s*): %w", envPrefix, err)
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Validate checa a config estaticamente (sem rede): campos obrigatórios,
// nomes de upstream únicos, coerência transport/command/url e sink/path.
func (c *Config) Validate() error {
	var errs []error

	if strings.TrimSpace(c.Listen) == "" {
		errs = append(errs, errors.New("listen: obrigatório"))
	}

	if len(c.Upstreams) == 0 {
		errs = append(errs, errors.New("upstreams: ao menos um é obrigatório"))
	}

	seen := make(map[string]struct{}, len(c.Upstreams))
	perUser := false
	for i, u := range c.Upstreams {
		who := fmt.Sprintf("upstreams[%d]", i)
		if strings.TrimSpace(u.Name) == "" {
			errs = append(errs, fmt.Errorf("%s.name: obrigatório", who))
		} else {
			who = fmt.Sprintf("upstreams[%q]", u.Name)
			if _, dup := seen[u.Name]; dup {
				errs = append(errs, fmt.Errorf("%s.name: duplicado", who))
			}
			seen[u.Name] = struct{}{}
		}

		switch u.Transport {
		case TransportStdio:
			if len(u.Command) == 0 {
				errs = append(errs, fmt.Errorf("%s.command: obrigatório para transport=stdio", who))
			}
			if u.Auth.Type != "" || u.BearerToken != "" {
				errs = append(errs, fmt.Errorf("%s.auth: auth sul só se aplica a transport=http", who))
			}
		case TransportHTTP:
			if strings.TrimSpace(u.URL) == "" {
				errs = append(errs, fmt.Errorf("%s.url: obrigatório para transport=http", who))
			}
		case "":
			errs = append(errs, fmt.Errorf("%s.transport: obrigatório (stdio|http)", who))
		default:
			errs = append(errs, fmt.Errorf("%s.transport: %q inválido (use stdio|http)", who, u.Transport))
		}

		errs = append(errs, u.Auth.validate(who)...)
		if u.Auth.Type == SouthAuthPerUser {
			perUser = true
		}
	}

	errs = append(errs, c.Credentials.validate(perUser)...)

	switch c.Audit.Sink {
	case SinkStdout:
	case SinkFile:
		if strings.TrimSpace(c.Audit.Path) == "" {
			errs = append(errs, errors.New("audit.path: obrigatório para audit.sink=file"))
		}
	case "":
		errs = append(errs, errors.New("audit.sink: obrigatório (stdout|file)"))
	default:
		errs = append(errs, fmt.Errorf("audit.sink: %q inválido (use stdout|file)", c.Audit.Sink))
	}

	errs = append(errs, c.Auth.validate()...)
	errs = append(errs, c.Policy.validate()...)
	errs = append(errs, c.RateLimit.validate()...)

	return errors.Join(errs...)
}

// validate checa o bloco de auth. Mode vazio é válido (=> none, sem auth).
func (a Auth) validate() []error {
	var errs []error
	switch a.Mode {
	case "", AuthNone:
		// Sem auth: api_keys/jwt são ignorados; nada a validar.
	case AuthAPIKey:
		if len(a.APIKeys) == 0 {
			errs = append(errs, errors.New("auth.api_keys: ao menos uma é obrigatória para mode=apikey"))
		}
		seen := make(map[string]struct{}, len(a.APIKeys))
		for i, k := range a.APIKeys {
			who := fmt.Sprintf("auth.api_keys[%d]", i)
			if strings.TrimSpace(k.Key) == "" {
				errs = append(errs, fmt.Errorf("%s.key: obrigatório", who))
			} else if _, dup := seen[k.Key]; dup {
				errs = append(errs, fmt.Errorf("%s.key: duplicado", who))
			} else {
				seen[k.Key] = struct{}{}
			}
			if strings.TrimSpace(k.Principal) == "" {
				errs = append(errs, fmt.Errorf("%s.principal: obrigatório", who))
			}
		}
	case AuthJWT:
		if strings.TrimSpace(a.JWT.Secret) == "" {
			errs = append(errs, errors.New("auth.jwt.secret: obrigatório para mode=jwt (HS256)"))
		}
	case AuthOIDC:
		// Precisa de pelo menos um modo de localizar as chaves: jwks_uri explícito
		// ou issuer (para OIDC discovery). default-deny de config ambígua.
		if strings.TrimSpace(a.OIDC.JWKSURI) == "" && strings.TrimSpace(a.OIDC.Issuer) == "" {
			errs = append(errs, errors.New("auth.oidc: defina jwks_uri ou issuer (para discovery) em mode=oidc"))
		}
		for _, alg := range a.OIDC.Algorithms {
			if alg != "RS256" {
				errs = append(errs, fmt.Errorf("auth.oidc.algorithms: %q não suportado (apenas RS256)", alg))
			}
		}
	default:
		errs = append(errs, fmt.Errorf("auth.mode: %q inválido (use none|apikey|jwt|oidc)", a.Mode))
	}
	return errs
}

// validate checa o bloco de auth sul de um upstream. Vazio é válido (=> legado:
// service_bearer se bearer_token estiver preenchido, senão sem auth sul).
func (u UpstreamAuth) validate(who string) []error {
	var errs []error
	switch u.Type {
	case "", SouthAuthServiceBearer:
		// service_bearer: o segredo vem de bearer_env OU do bearer_token inline.
	case SouthAuthServiceOAuthCC:
		if strings.TrimSpace(u.OAuth.TokenURL) == "" {
			errs = append(errs, fmt.Errorf("%s.auth.oauth.token_url: obrigatório para type=service_oauth_cc", who))
		}
		if strings.TrimSpace(u.OAuth.ClientIDEnv) == "" {
			errs = append(errs, fmt.Errorf("%s.auth.oauth.client_id_env: obrigatório para type=service_oauth_cc", who))
		}
		if strings.TrimSpace(u.OAuth.ClientSecretEnv) == "" {
			errs = append(errs, fmt.Errorf("%s.auth.oauth.client_secret_env: obrigatório para type=service_oauth_cc", who))
		}
	case SouthAuthPerUser:
		// O vault é validado globalmente (precisa estar configurado se há per_user).
	default:
		errs = append(errs, fmt.Errorf("%s.auth.type: %q inválido (use service_bearer|service_oauth_cc|per_user)", who, u.Type))
	}
	return errs
}

// validate checa o vault de credenciais sul. Só é exigido quando há ao menos um
// upstream per_user (perUser=true); caso contrário, um bloco vazio é válido.
func (c Credentials) validate(perUser bool) []error {
	var errs []error
	if !perUser {
		if c.Store != "" && c.Store != CredStoreFile {
			errs = append(errs, fmt.Errorf("credentials.store: %q inválido (use file)", c.Store))
		}
		return errs
	}
	switch c.Store {
	case CredStoreFile:
		if strings.TrimSpace(c.File.Path) == "" {
			errs = append(errs, errors.New("credentials.file.path: obrigatório para store=file"))
		}
		if strings.TrimSpace(c.File.KeyEnv) == "" {
			errs = append(errs, errors.New("credentials.file.key_env: obrigatório para store=file"))
		}
	case "":
		errs = append(errs, errors.New("credentials.store: obrigatório quando há upstream com auth.type=per_user"))
	default:
		errs = append(errs, fmt.Errorf("credentials.store: %q inválido (use file)", c.Store))
	}
	return errs
}

// validate checa o bloco de política. Default vazio é válido (=> deny).
func (p Policy) validate() []error {
	var errs []error
	if err := validatePolicyDefault("policy.default", p.Default); err != nil {
		errs = append(errs, err)
	}
	for agent, ap := range p.Agents {
		if strings.TrimSpace(agent) == "" {
			errs = append(errs, errors.New("policy.agents: chave de agente vazia"))
		}
		field := fmt.Sprintf("policy.agents[%q].default", agent)
		if err := validatePolicyDefault(field, ap.Default); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// validatePolicyDefault aceita "", "deny" ou "allow".
func validatePolicyDefault(field, v string) error {
	switch v {
	case "", PolicyDeny, PolicyAllow:
		return nil
	default:
		return fmt.Errorf("%s: %q inválido (use deny|allow)", field, v)
	}
}

// validate checa o bloco de rate limit. RPS<=0 desliga; com RPS>0 o burst
// precisa ser >=1, senão o bucket nasce vazio e bloqueia tudo.
func (r RateLimit) validate() []error {
	var errs []error
	if r.RPS < 0 {
		errs = append(errs, fmt.Errorf("rate_limit.rps: %g inválido (>=0; 0 desliga)", r.RPS))
	}
	if r.Burst < 0 {
		errs = append(errs, fmt.Errorf("rate_limit.burst: %d inválido (>=0)", r.Burst))
	}
	if r.RPS > 0 && r.Burst < 1 {
		errs = append(errs, fmt.Errorf("rate_limit.burst: %d inválido (>=1 quando rps>0)", r.Burst))
	}
	return errs
}
