package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func validCfg() *Config {
	return &Config{
		Listen: ":8080",
		Upstreams: []Upstream{
			{Name: "github", Transport: TransportStdio, Command: []string{"github-mcp-server"}},
			{Name: "pg", Transport: TransportHTTP, URL: "http://localhost:9001/mcp"},
		},
		Audit: Audit{Sink: SinkStdout, Format: "jsonl"},
	}
}

func TestValidateOK(t *testing.T) {
	if err := validCfg().Validate(); err != nil {
		t.Fatalf("config válida deveria passar, got: %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{"sem listen", func(c *Config) { c.Listen = "" }, "listen"},
		{"sem upstreams", func(c *Config) { c.Upstreams = nil }, "upstreams"},
		{"nome duplicado", func(c *Config) { c.Upstreams[1].Name = "github" }, "duplicado"},
		{"stdio sem command", func(c *Config) { c.Upstreams[0].Command = nil }, "command"},
		{"http sem url", func(c *Config) { c.Upstreams[1].URL = "" }, "url"},
		{"transport inválido", func(c *Config) { c.Upstreams[0].Transport = "grpc" }, "inválido"},
		{"sink inválido", func(c *Config) { c.Audit.Sink = "syslog" }, "audit.sink"},
		{"file sem path", func(c *Config) { c.Audit.Sink = SinkFile; c.Audit.Path = "" }, "audit.path"},
		{"policy.default inválido", func(c *Config) { c.Policy.Default = "maybe" }, "policy.default"},
		{"agent.default inválido", func(c *Config) {
			c.Policy.Agents = map[string]AgentPolicy{"bot": {Default: "perhaps"}}
		}, "policy.agents"},
		{"rps negativo", func(c *Config) { c.RateLimit.RPS = -1 }, "rate_limit.rps"},
		{"burst negativo", func(c *Config) { c.RateLimit.Burst = -1 }, "rate_limit.burst"},
		{"burst zero com rps", func(c *Config) { c.RateLimit.RPS = 5; c.RateLimit.Burst = 0 }, "rate_limit.burst"},
		{"auth.mode inválido", func(c *Config) { c.Auth.Mode = "saml" }, "auth.mode"},
		{"apikey sem keys", func(c *Config) { c.Auth.Mode = AuthAPIKey }, "auth.api_keys"},
		{"apikey sem principal", func(c *Config) {
			c.Auth = Auth{Mode: AuthAPIKey, APIKeys: []APIKey{{Key: "k"}}}
		}, "principal"},
		{"apikey key duplicada", func(c *Config) {
			c.Auth = Auth{Mode: AuthAPIKey, APIKeys: []APIKey{{Key: "k", Principal: "a"}, {Key: "k", Principal: "b"}}}
		}, "duplicado"},
		{"jwt sem secret", func(c *Config) { c.Auth.Mode = AuthJWT }, "auth.jwt.secret"},
		{"oidc sem issuer/jwks", func(c *Config) { c.Auth = Auth{Mode: AuthOIDC} }, "auth.oidc"},
		{"oidc alg não-RS256", func(c *Config) {
			c.Auth = Auth{Mode: AuthOIDC, OIDC: OIDC{Issuer: "https://idp", Algorithms: []string{"ES256"}}}
		}, "algorithms"},
		{"south auth.type inválido", func(c *Config) { c.Upstreams[1].Auth = UpstreamAuth{Type: "magic"} }, "auth.type"},
		{"south auth em stdio", func(c *Config) {
			c.Upstreams[0].Auth = UpstreamAuth{Type: SouthAuthServiceBearer}
		}, "auth sul só se aplica"},
		{"oauth_cc sem token_url", func(c *Config) {
			c.Upstreams[1].Auth = UpstreamAuth{Type: SouthAuthServiceOAuthCC, OAuth: UpstreamOAuthCC{ClientIDEnv: "ID", ClientSecretEnv: "SEC"}}
		}, "token_url"},
		{"per_user sem vault", func(c *Config) { c.Upstreams[1].Auth = UpstreamAuth{Type: SouthAuthPerUser} }, "credentials.store"},
		{"per_user file sem path", func(c *Config) {
			c.Upstreams[1].Auth = UpstreamAuth{Type: SouthAuthPerUser}
			c.Credentials = Credentials{Store: CredStoreFile, File: CredentialsFile{KeyEnv: "K"}}
		}, "credentials.file.path"},
		{"credentials.store inválido", func(c *Config) { c.Credentials = Credentials{Store: "vault"} }, "credentials.store"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validCfg()
			tt.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("esperava erro contendo %q, got nil", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("erro %q não contém %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestValidateAuthModesOK(t *testing.T) {
	cases := []func(*Config){
		func(c *Config) { c.Auth = Auth{} },               // vazio => none
		func(c *Config) { c.Auth = Auth{Mode: AuthNone} }, // none explícito
		func(c *Config) { c.Auth = Auth{Mode: AuthAPIKey, APIKeys: []APIKey{{Key: "k", Principal: "ci"}}} },
		func(c *Config) { c.Auth = Auth{Mode: AuthJWT, JWT: JWT{Secret: "s"}} },
		func(c *Config) { c.Auth = Auth{Mode: AuthOIDC, OIDC: OIDC{Issuer: "https://idp"}} },                 // discovery
		func(c *Config) { c.Auth = Auth{Mode: AuthOIDC, OIDC: OIDC{JWKSURI: "https://idp/jwks"}} },           // jwks explícito
		func(c *Config) { c.Upstreams[1].Auth = UpstreamAuth{Type: SouthAuthServiceBearer, BearerEnv: "T"} }, // service_bearer
		func(c *Config) { // per_user com vault de arquivo
			c.Upstreams[1].Auth = UpstreamAuth{Type: SouthAuthPerUser}
			c.Credentials = Credentials{Store: CredStoreFile, File: CredentialsFile{Path: "creds.enc", KeyEnv: "K"}}
		},
	}
	for i, mutate := range cases {
		c := validCfg()
		mutate(c)
		if err := c.Validate(); err != nil {
			t.Errorf("caso %d: auth válida deveria passar, got: %v", i, err)
		}
	}
}

func TestLoadExampleConfig(t *testing.T) {
	// O arquivo de exemplo versionado precisa sempre validar.
	path := filepath.Join("..", "..", "configs", "mcpgate.example.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("config de exemplo deveria carregar: %v", err)
	}
	if len(cfg.Upstreams) == 0 {
		t.Fatal("config de exemplo sem upstreams")
	}
}
