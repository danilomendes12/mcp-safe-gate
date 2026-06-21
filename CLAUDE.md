# mcpgate

Gateway de governança open source para MCP, escrito em Go. Reverse proxy entre agentes de IA (clientes MCP) e servidores MCP upstream, aplicando autenticação, política por ferramenta, inspeção e auditoria. Objetivo: leve, single-binary, self-host trivial.

Docs de referência (leia antes de mudanças grandes — não duplicar aqui):
- @docs/PRODUCT.md — visão de produto, arquitetura e diferencial
- @docs/BACKLOG.md — roadmap por épicos (E0–E8)
- @docs/SETUP.md — ambiente, tooling e Taskfile

## Arquitetura

Para os agentes, o gateway é um `mcp.Server`; para cada upstream, um `mcp.Client`. Toda chamada de ferramenta atravessa 5 estágios — um pacote em `internal/` para cada:

- `internal/auth` — estágio 1: autentica o cliente + resolve a identidade do humano por trás do agente
- `internal/policy` — estágios 2 e 3: RBAC por ferramenta (default deny) + descoberta filtrada de `tools/list`
- `internal/inspect` — estágio 4: guardrails (prompt injection, redação de PII)
- `internal/proxy` — estágio 5: roteamento via `mcp.Client` + injeção de segredo do upstream
- `internal/audit` — transversal: log estruturado JSONL (`slog`) + OpenTelemetry
- `internal/config` — carrega `mcpgate.yaml` (upstreams + política)

## Stack

- Go (stable mais recente). SDK oficial: `github.com/modelcontextprotocol/go-sdk` — pacotes `mcp`, `jsonrpc`, `auth`, `oauthex`.
- Config: `koanf`. CLI: `cobra`. Logging: `log/slog` (stdlib). Observabilidade: OpenTelemetry.

## Comandos

- `task dev` — hot reload (air)
- `task run` — sobe o gateway com a config de exemplo
- `task test` — `go test ./... -race -cover`
- `task lint` — `golangci-lint run`
- `task inspect` — abre o MCP Inspector apontando pro gateway

## Convenções

- Segurança default-deny: nada é permitido sem regra explícita na política.
- Dependências mínimas: prefira a stdlib antes de adicionar uma lib nova.
- Erros sempre tratados; nunca engolir exceção. Use `%w` para wrap.
- Testes de integração usam os transports in-memory do SDK (`mcp.NewInMemoryTransports`).
- Segredos de upstream NUNCA chegam ao agente.

## Segurança (referência viva: SAFE-MCP)

Modele e priorize defesas pelo SAFE-MCP (framework MITRE ATT&CK para MCP). Mapeie cada guardrail a um `SAFE-T` ID nos docs e no README. Mínimos de segurança do MVP:

- SAFE-T1001 (Tool Poisoning) — validar definições de tools vindas dos upstreams
- SAFE-T1102 (Prompt Injection) — inspeção de payload no estágio 4
- SAFE-T1201 (Rug Pull) — detectar mudança de definição de tool entre sessões
- SAFE-T1307 (Confused Deputy) — identidade verificada do bearer no estágio 1 (E4); o gateway age pelo principal real, não repassa cegamente
- SAFE-T1602 (Tool Enumeration) — descoberta filtrada no estágio 3 (E3): a tool fora da política some do `tools/list`, não só é bloqueada

## Regras de trabalho

- Antes de editar `auth`, `policy` ou `inspect`: explique o risco e qual estágio é afetado.
- Mudou comportamento do proxy? Rode `task test` e valide no MCP Inspector.
- Mantenha este arquivo curto e de alto sinal — aponte para os docs, não duplique.