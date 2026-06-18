// Package config carrega e valida a configuração do mcpgate (mcpgate.yaml).
//
// O schema inclui campos de estágios ainda não implementados (ex.: políticas
// de RBAC, E2) de propósito: queremos que o formato do arquivo nasça estável.
// Campos deferidos são parseados, mas não aplicados no MVP — ver Validate.
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

// Config é a configuração completa do gateway.
type Config struct {
	// Listen é o endereço do transporte HTTP voltado ao agente. Reservado para
	// um estágio posterior; no MVP o serve é stdio. Validado por estar presente.
	Listen string `koanf:"listen"`
	// Upstreams são os servidores MCP que o gateway fronteia.
	Upstreams []Upstream `koanf:"upstreams"`
	// Policies é parseado mas IGNORADO no MVP (motor de política é E2). Mantido
	// no schema para que o formato do arquivo seja estável desde já.
	Policies []Policy `koanf:"policies"`
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
}

// Policy é o formato (estável) de uma regra de política. Não aplicado no MVP.
type Policy struct {
	Role       string   `koanf:"role"`
	AllowTools []string `koanf:"allow_tools"`
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

	return errors.Join(errs...)
}
