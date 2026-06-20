# mcpgate

> Gateway de governança open source para MCP, em Go, como binário único: um reverse proxy entre seus agentes de IA e os servidores MCP upstream, auditando cada chamada de ferramenta.

Para os agentes, o mcpgate é um `mcp.Server`; para cada upstream, um `mcp.Client`. Toda chamada de ferramenta atravessa o gateway, que roteia e — nos próximos estágios — aplica identidade, política por ferramenta e guardrails de inspeção.

## MVP-0 — o que é

Este corte é a **demo de 5 minutos**: um **proxy passthrough verbatim** que fronteia upstreams MCP reais e **audita cada chamada em JSONL**.

- Descobre as tools de cada upstream no boot e as republica com **nome namespaced** (`<upstream>.<tool>`, ex.: `github.list_issues`) — mesmo com um único upstream.
- Repassa schema e argumentos **sem reinterpretar**: não inventa, não valida e não reescreve schema de tool.
- Emite **uma linha JSONL de auditoria por `tools/call`**, já com o campo `identity` (`"anonymous"` no MVP).
- Transportes de upstream: **stdio** (o gateway sobe o processo) e **HTTP streamable**.

## E2 — o que entrou

- **Transporte norte HTTP** (Streamable HTTP) como default do `serve`; `stdio` segue disponível via `--transport stdio`.
- **RBAC por ferramenta** (estágio 2) com postura **default-deny**: `allow_tools` / `deny_tools`, `deny` tem precedência, e regras opcionais por agente. A tool negada é bloqueada no `tools/call` com **erro JSON-RPC limpo** (`-32001`).
- **Rate limit por agente** (token bucket in-process): admissão antes do RBAC; ao estourar, erro JSON-RPC limpo (`-32002`) sem derrubar a conexão. Mapeia a defesa contra DoS por exaustão de recursos (SAFE-MCP / Impact, ATK-TA0040).
- **Auditoria** passa a registrar `decision` (allow/deny) e o `principal` (campo `identity`) em **toda** `tools/call`.

## E2 — o que NÃO é (ainda)

Filtrar `tools/list` para esconder a tool negada (E3 — no E2 ela **continua visível** e só é barrada no `tools/call`), identidade/OAuth real (E4 — o resolver devolve um principal provisório), inspeção/guardrails — prompt injection, PII, SAFE-MCP (E5), idempotência/circuit breaker/reconexão de upstream (E6/E9–E12), traces OpenTelemetry. Os pacotes desses estágios já existem como placeholders.

## Quickstart

```bash
# 1. Compilar o binário
task build           # ou: go build -o bin/mcpgate ./cmd/mcpgate

# 2. Editar a config: aponte para um upstream MCP real
$EDITOR configs/mcpgate.example.yaml

# 3. Validar a config estaticamente (sem rede)
go run ./cmd/mcpgate validate-config --config configs/mcpgate.example.yaml

# 4. Subir o gateway (HTTP por default) e brincar
task run                       # serve --transport http
# ou, no MCP Inspector sobre stdio:
task inspect
```

No `tools/list` você verá os nomes namespaced; uma tool permitida retorna o resultado real do upstream e uma negada volta erro JSON-RPC — sempre emitindo uma linha de auditoria. Para a validação completa do E2 (allow/deny/default-deny/rate limit), veja **[Smoke test](#smoke-test-validação-manual)**.

## Comandos

| Comando | Descrição |
| --- | --- |
| `mcpgate serve --config <path> [--transport http\|stdio]` | Carrega a config e sobe o proxy. Default `http`; `stdio` para laptop/single-user. |
| `mcpgate validate-config --config <path>` | Valida o arquivo estaticamente (inclui política e rate limit); sai ≠ 0 com mensagem clara em caso de erro. |

## Configuração

Ver [configs/mcpgate.example.yaml](configs/mcpgate.example.yaml). Qualquer chave pode ser sobrescrita por ambiente com o prefixo `MCPGATE_` (ex.: `MCPGATE_AUDIT_SINK=file`). Os blocos relevantes do E2 são `policy` (RBAC default-deny), `rate_limit` (quota por agente) e `default_agent` (principal provisório).

## Smoke test (validação manual)

Prova do E2 de ponta a ponta sobre o transporte HTTP real. Usa
[configs/mcpgate.local.yaml](configs/mcpgate.local.yaml), que sobe um único
upstream stdio (o `server-everything` via `npx`) com a política:
`default: deny`, `allow_tools: [everything.echo]`, `deny_tools: [everything.add]`.

**1. Build**

```bash
task build      # ou: CGO_ENABLED=0 go build -o bin/mcpgate ./cmd/mcpgate
```

**2. Validar a config** — esperado: imprime `OK` e sai `0`.

```bash
./bin/mcpgate validate-config --config configs/mcpgate.local.yaml
# Config inválida sai ≠ 0 com mensagem clara, ex.:
echo 'listen: ":8080"
upstreams: [{name: x, transport: stdio, command: ["true"]}]
audit: {sink: stdout}
policy: {default: talvez}' > /tmp/bad.yaml
./bin/mcpgate validate-config --config /tmp/bad.yaml   # => "policy.default: ... inválido", exit 1
```

**3. Subir em HTTP** — esperado: linha de auditoria `gateway ouvindo … transport=http addr=:8080`.

```bash
./bin/mcpgate serve --transport http --config configs/mcpgate.local.yaml &
tail -f mcpgate-audit.jsonl   # acompanhe a auditoria em outro terminal
```

> A auditoria desta config vai para o arquivo `mcpgate-audit.jsonl`. O default do
> SDK protege contra DNS rebinding mas **não** barra o Inspector/cURL local
> (Host `localhost`) — nenhuma flag de escape é necessária.

**4. Inspector → endpoint HTTP (opcional, visual)**

```bash
task inspect-http   # abre a UI; escolha "Streamable HTTP" e aponte para http://localhost:8080
```

No `tools/list` aparecem os nomes namespaced — inclusive `everything.add`
(negada): **sumir da lista é E3**; aqui ela só é bloqueada no `tools/call`.

**5. Abrir uma sessão MCP (cURL)** — guarda o `Mcp-Session-Id`:

```bash
URL=http://localhost:8080
H='-H Content-Type:application/json -H Accept:application/json,text/event-stream'
SID=$(curl -sS -D - -o /dev/null -X POST $URL $H \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  | awk -F': ' 'tolower($1)=="mcp-session-id"{gsub(/\r/,"",$2);print $2}')
curl -sS -o /dev/null -X POST $URL $H -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
call(){ curl -sS -X POST $URL $H -H "Mcp-Session-Id: $SID" -d "$1" | grep '^data:' | sed 's/^data: //'; }
```

**6. Chamada permitida** — `everything.echo` está no `allow`:

```bash
call '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"everything.echo","arguments":{"message":"oi"}}}'
# => {"result":{"content":[{"type":"text","text":"Echo: oi"}]}}   (resultado real do upstream)
# auditoria: ... "tool":"everything.echo","identity":"anonymous","decision":"allow","ok":true
```

**7. Chamada negada (deny explícito)** — `everything.add` está no `deny`:

```bash
call '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"everything.add","arguments":{"a":1,"b":2}}}'
# => {"error":{"code":-32001,"message":"acesso negado à tool \"everything.add\" ... (deny_tools)"}}
# não foi ao upstream. auditoria: ... "decision":"deny","error":"deny_tools"
```

**8. Default-deny** — `everything.printEnv` não está em lista nenhuma:

```bash
call '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"everything.printEnv","arguments":{}}}'
# => {"error":{"code":-32001,"message":"... (default_deny)"}}
# auditoria: ... "decision":"deny","error":"default_deny"
```

**9. Rate limit** — a admissão (`rps:5`, `burst:20`) roda antes do RBAC; dispare
bem acima do burst de uma vez:

```bash
for n in $(seq 1 30); do
  call "{\"jsonrpc\":\"2.0\",\"id\":$((100+n)),\"method\":\"tools/call\",\"params\":{\"name\":\"everything.echo\",\"arguments\":{\"message\":\"r\"}}}"
done | sort | uniq -c
# => parte com "result" (admitidas) e parte com {"code":-32002,"message":"rate limit excedido ..."}
# a conexão segue VIVA (um novo call após o estouro responde normalmente).
```

**10. Regressão stdio** — o mesmo `p.server` roda em stdio:

```bash
task inspect   # sobe o gateway como subprocesso stdio e repassa
```

## Stack

- **Go 1.25+** — binário único.
- SDK oficial [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk).
- Config: [`koanf/v2`](https://github.com/knadh/koanf). CLI: [`cobra`](https://github.com/spf13/cobra). Auditoria: `log/slog` (stdlib).
