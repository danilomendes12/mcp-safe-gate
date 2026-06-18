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
