# mcpgate

> Gateway de governança open source para MCP, em Go, como binário único: um reverse proxy entre seus agentes de IA e os servidores MCP upstream, auditando cada chamada de ferramenta.

Para os agentes, o mcpgate é um `mcp.Server`; para cada upstream, um `mcp.Client`. Toda chamada de ferramenta atravessa o gateway, que roteia e — nos próximos estágios — aplica identidade, política por ferramenta e guardrails de inspeção.

## MVP-0 — o que é

Este corte é a **demo de 5 minutos**: um **proxy passthrough verbatim** que fronteia upstreams MCP reais e **audita cada chamada em JSONL**.

- Descobre as tools de cada upstream no boot e as republica com **nome namespaced** (`<upstream>.<tool>`, ex.: `github.list_issues`) — mesmo com um único upstream.
- Repassa schema e argumentos **sem reinterpretar**: não inventa, não valida e não reescreve schema de tool.
- Emite **uma linha JSONL de auditoria por `tools/call`**, já com o campo `identity` (`"anonymous"` no MVP).
- Transportes de upstream: **stdio** (o gateway sobe o processo) e **HTTP streamable**.

## MVP-0 — o que NÃO é (ainda)

Política/RBAC e rejeição de `tools/call` (E2), descoberta filtrada (E3), identidade/OAuth (E4), inspeção/guardrails — prompt injection, PII, SAFE-MCP (E5), rate limiting, traces OpenTelemetry e o transporte HTTP do lado do agente (o `serve` é stdio). Os pacotes desses estágios já existem como placeholders e o seam de middleware está plugado — sem lógica.

## Quickstart

```bash
# 1. Compilar o binário
task build           # ou: go build -o bin/mcpgate ./cmd/mcpgate

# 2. Editar a config: aponte para um upstream MCP real
$EDITOR configs/mcpgate.example.yaml

# 3. Validar a config estaticamente (sem rede)
go run ./cmd/mcpgate validate-config --config configs/mcpgate.example.yaml

# 4. Subir no MCP Inspector e brincar
task inspect
```

No Inspector você verá `tools/list` com os nomes namespaced, e cada chamada de tool retorna o resultado real do upstream — emitindo uma linha de auditoria no terminal.

## Comandos

| Comando | Descrição |
| --- | --- |
| `mcpgate serve --config <path>` | Carrega a config e sobe o proxy (stdio). |
| `mcpgate validate-config --config <path>` | Valida o arquivo estaticamente; sai ≠ 0 com mensagem clara em caso de erro. |

## Configuração

Ver [configs/mcpgate.example.yaml](configs/mcpgate.example.yaml). Qualquer chave pode ser sobrescrita por ambiente com o prefixo `MCPGATE_` (ex.: `MCPGATE_AUDIT_SINK=file`).

## Stack

- **Go 1.25+** — binário único.
- SDK oficial [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk).
- Config: [`koanf/v2`](https://github.com/knadh/koanf). CLI: [`cobra`](https://github.com/spf13/cobra). Auditoria: `log/slog` (stdlib).
