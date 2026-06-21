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
	// override por ambiente (ex.: MCPGATE_UPSTREAMS_0_BEARER_TOKEN).
	BearerToken string `koanf:"bearer_token"`
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
	// APIKeys mapeia cada key estática a um principal (mode=apikey).
	APIKeys []APIKey `koanf:"api_keys"`
	// JWT configura a verificação de JWT HS256 (mode=jwt).
	JWT JWT `koanf:"jwt"`
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
		case TransportHTTP:
			if strings.TrimSpace(u.URL) == "" {
				errs = append(errs, fmt.Errorf("%s.url: obrigatório para transport=http", who))
			}
		case "":
			errs = append(errs, fmt.Errorf("%s.transport: obrigatório (stdio|http)", who))
		default:
			errs = append(errs, fmt.Errorf("%s.transport: %q inválido (use stdio|http)", who, u.Transport))
		}
	}

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
	default:
		errs = append(errs, fmt.Errorf("auth.mode: %q inválido (use none|apikey|jwt)", a.Mode))
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
