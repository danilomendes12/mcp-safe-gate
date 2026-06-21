# mcpgate

> Gateway de governança open source para MCP, em Go, como binário único: um reverse proxy entre seus agentes de IA e os servidores MCP upstream, auditando cada chamada de ferramenta.

Para os agentes, o mcpgate é um `mcp.Server`; para cada upstream, um `mcp.Client`. Toda chamada de ferramenta atravessa o gateway, que roteia, aplica **política por ferramenta** (RBAC default-deny) e **rate limit**, audita cada chamada — e, nos próximos estágios, vai resolver **identidade** real e aplicar **guardrails de inspeção**.

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

## E3 + E4 — o que entrou

- **Descoberta filtrada** (estágio 3 / E3): o `tools/list` agora é **filtrado pela política** — a tool que o principal não pode chamar fica **invisível** na listagem, não só bloqueada no `tools/call`. Mesmo `Engine` do RBAC, então o que some da lista é exatamente o que seria negado. Mitiga enumeração de tools / capability mapping (**SAFE-T1602**).
- **Identidade + auth** (estágio 1 / E4), **só no caminho HTTP**: o handler é envolvido pelo `RequireBearerToken` do SDK. Modos config-driven:
  - `apikey` — API key estática mapeada a um principal (`auth.api_keys`);
  - `jwt` — JWT **HS256** (segredo compartilhado), com validação de assinatura, `exp`, scopes e (opcional) `iss`/`aud`. O principal sai da claim configurável (default `sub`);
  - `oidc` — JWT **RS256 de um IdP externo**, validado via **JWKS**: as chaves públicas vêm do `jwks_uri` (ou descoberto via `<issuer>/.well-known/openid-configuration`), casadas pelo `kid`, cacheadas com **rotação**. Valida assinatura, `iss` e `aud`. Fecha a porta a um **Rogue Authorization Server (SAFE-T1306)**.

  O principal resolvido do token substitui o `default_agent` e alimenta RBAC, descoberta filtrada e auditoria. Sem token → **401 + `WWW-Authenticate`**; scope insuficiente → **403**. Mitiga confused deputy (**SAFE-T1307**): o gateway age pela identidade verificada do humano por trás do agente.
  - **Protected Resource Metadata (RFC 9728)**: com `auth.resource` + um issuer, o gateway publica `/.well-known/oauth-protected-resource` para o cliente MCP (e o Inspector) descobrirem o authorization server a partir do `WWW-Authenticate`.
- **Auth sul (upstream)** — **com qual credencial o gateway chama o upstream** (E4-sul). Por upstream, `auth.type`:
  - `service_bearer` — bearer estático único do gateway (compat: `bearer_token`/`bearer_env`). OK quando a tool **não** age por conta de usuário;
  - `service_oauth_cc` — conta de serviço via **OAuth client-credentials** (token que renova sozinho), no mesmo seam `HTTPClient`;
  - `per_user` — **autorização delegada**: a credencial sul é **derivada do principal do norte** (`(principal, upstream)` → credencial daquele usuário, num **vault cifrado** AES-256-GCM). Garante **no-passthrough** (o bearer do norte **nunca** vai ao upstream), **fail-closed** (sem credencial → negado, nunca cai na de outro usuário) e **auditoria identity-aware** (`upstream_cred` registra QUAL credencial foi usada, sem o segredo). Mitiga **confused deputy (SAFE-T1307)** e **token scope substitution (SAFE-T1308)**.
- **Caminho stdio inalterado**: sem auth, identidade `anonymous` — o self-host de 5 min segue igual.

## O que NÃO é (ainda)

Inspeção/guardrails — prompt injection, PII, SAFE-MCP de payload (E5), idempotência/circuit breaker/reconexão de upstream (E6/E9–E12), traces OpenTelemetry. Os pacotes desses estágios já existem como placeholders.

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

No `tools/list` você verá só os nomes namespaced que o principal pode chamar (E3); uma tool permitida retorna o resultado real do upstream, e chamar direto uma tool oculta/negada volta erro JSON-RPC — sempre emitindo uma linha de auditoria. Para a validação completa (auth/discovery/allow/deny/rate limit), veja **[Smoke test](#smoke-test-validação-manual)**.

## Comandos

| Comando | Descrição |
| --- | --- |
| `mcpgate serve --config <path> [--transport http\|stdio]` | Carrega a config e sobe o proxy. Default `http` (auth via bloco `auth`); `stdio` para laptop/single-user (sem auth, `anonymous`). |
| `mcpgate validate-config --config <path>` | Valida o arquivo estaticamente (inclui política e rate limit); sai ≠ 0 com mensagem clara em caso de erro. |

## Configuração

Ver [configs/mcpgate.example.yaml](configs/mcpgate.example.yaml). Qualquer chave pode ser sobrescrita por ambiente com o prefixo `MCPGATE_` (ex.: `MCPGATE_AUDIT_SINK=file`, `MCPGATE_AUTH_JWT_SECRET=…`) — prático para não versionar segredos. Blocos principais: `auth` (autenticação norte: `none`/`apikey`/`jwt`, scopes e keys — só HTTP), `policy` (RBAC default-deny, base também da descoberta filtrada do E3), `rate_limit` (quota por agente), `default_agent` (principal do caminho stdio / HTTP sem auth) e `upstreams[].bearer_token` (auth sul, opcional).

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

No `tools/list` aparece **só `everything.echo`** (a permitida): com o E3 a tool
negada `everything.add` e a default-deny `everything.printEnv` ficam **invisíveis**.
Chamá-las direto ainda erra limpo (ver passos 7–8) — invisível **e** bloqueada.

**5. Abrir uma sessão MCP (cURL)** — guarda o `Mcp-Session-Id` e define o helper
`call` (funciona em bash e zsh):

```bash
URL=http://localhost:8080

# initialize: captura o Mcp-Session-Id do header de resposta
SID=$(curl -sS -D - -o /dev/null -X POST "$URL" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  | awk -F': ' 'tolower($1)=="mcp-session-id"{gsub(/\r/,"",$2);print $2}')

# helper: manda um tools/call e mostra só o payload da resposta SSE
call(){ curl -sS -X POST "$URL" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H "Mcp-Session-Id: $SID" \
  -d "$1" | grep '^data:' | sed 's/^data: //'; }

# completa o handshake
curl -sS -o /dev/null -X POST "$URL" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
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
  call "{\"jsonrpc\":\"2.0\",\"id\":$n,\"method\":\"tools/call\",\"params\":{\"name\":\"everything.echo\",\"arguments\":{\"message\":\"r\"}}}"
done | grep -o '"result"\|-32002' | sort | uniq -c
# => tally tipo:  17 "result"   e   13 -32002
# parte admitida + parte barrada por rate limit. A conexão segue VIVA:
# um novo `call` depois do estouro volta a responder normalmente.
```

**10. Regressão stdio** — o mesmo `p.server` roda em stdio:

```bash
task inspect   # sobe o gateway como subprocesso stdio e repassa
```

### Auth norte (E4) — prova sobre HTTP, sem mocks externos

Use [configs/mcpgate.auth.yaml](configs/mcpgate.auth.yaml): mesmo upstream `everything`,
mas com `auth.mode: apikey` e duas keys — `alice-key` (com o scope `tools:call`) e
`bob-key` (sem o scope). A autenticação é o próprio gateway validando o
`Authorization: Bearer`; não é preciso subir nenhum servidor de identidade.

```bash
./bin/mcpgate serve --config configs/mcpgate.auth.yaml &   # transport http (default)
URL=http://localhost:8080
```

**A) Sem token → 401 + `WWW-Authenticate`:**

```bash
curl -sS -o /dev/null -w '%{http_code}\n%header{www-authenticate}\n' -X POST "$URL" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping"}'
# => 401
#    Bearer resource_metadata="...", scope="tools:call"
```

**B) Token sem o scope exigido → 403:**

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$URL" -H 'Authorization: Bearer bob-key' \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping"}'
# => 403   (insufficient scope)
```

**C) Token válido → handshake passa e `tools/list` vem filtrado pelo principal:**

```bash
TOKEN="alice-key"
SID=$(curl -sS -D - -o /dev/null -X POST "$URL" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  | awk -F': ' 'tolower($1)=="mcp-session-id"{gsub(/\r/,"",$2);print $2}')

curl -sS -o /dev/null -X POST "$URL" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H "Mcp-Session-Id: $SID" -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

curl -sS -X POST "$URL" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | grep '^data:' | sed 's/^data: //'
# => só everything.echo na lista (política do principal alice + E3); auditoria com "identity":"alice"
```

> **JWT em vez de API key:** troque o bloco por `auth: { mode: jwt, jwt: { secret: "..." } }`
> e mande um JWT HS256 com claim `sub` (o principal) e `exp`. Token expirado → 401;
> assinatura/`alg` inválidos → 401; falta de scope exigido → 403.

O caminho **stdio ignora `auth`** por completo (identidade `anonymous`).

### Smoke A — IdP externo de verdade (norte, `mode: oidc` / JWKS + RFC 9728)

Prova que um **token RS256 de um IdP** autentica, o principal correto chega ao RBAC
e à descoberta filtrada, e o gateway publica o Protected Resource Metadata.

Use [configs/mcpgate.oidc.yaml](configs/mcpgate.oidc.yaml) e troque `issuer`/`audience`
pelos do seu IdP (Auth0, Keycloak, Google, Entra ID…). Com só o `issuer`, o `jwks_uri`
é descoberto via `<issuer>/.well-known/openid-configuration`.

```bash
./bin/mcpgate serve --config configs/mcpgate.oidc.yaml &
URL=http://localhost:8080

# Protected Resource Metadata (RFC 9728): público, fora da auth. O cliente MCP usa
# isto + o WWW-Authenticate de um 401 para achar o authorization server.
curl -sS "$URL/.well-known/oauth-protected-resource" | jq .
# => {"resource":"http://localhost:8080","authorization_servers":["https://YOUR-IDP..."],...}

# Pegue um access token RS256 do seu IdP (client_credentials/device code/etc.):
TOKEN="<jwt-rs256-do-idp>"

# Handshake + tools/list: o principal vem do `sub` do token e a lista é filtrada (E3).
SID=$(curl -sS -D - -o /dev/null -X POST "$URL" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  | awk -F': ' 'tolower($1)=="mcp-session-id"{gsub(/\r/,"",$2);print $2}')
# token assinado por outra chave / kid desconhecido / iss|aud errados / expirado => 401
# auditoria: "identity":"<sub-do-idp>"
```

> **Sem um IdP à mão?** A suíte automatizada já prova o caminho RS256/JWKS ponta a
> ponta (chave de teste gerada no teste, JWKS servido por `httptest`, rotação de
> `kid`, `iss`/`aud`/assinatura inválidos, e o endpoint RFC 9728):
> `go test ./internal/auth/ -run 'OIDC|JWKS|Metadata' -v`.

### Smoke B — Autorização delegada no sul (`auth.type: per_user`, E4-sul)

Prova que **o usuário A só acessa a conta de A**, que **a ausência de credencial nega**
(fail-closed) e que **o token do norte não vaza** ao upstream (no-passthrough). Usa um
upstream HTTP `per_user` (ex.: o bloco `github` de [configs/mcpgate.example.yaml](configs/mcpgate.example.yaml))
e o **vault cifrado**.

```bash
# 1. Gere a chave do vault (AES-256, base64) e enrole a credencial de cada usuário.
export MCPGATE_CRED_KEY=$(head -c 32 /dev/urandom | base64)
CFG=configs/mcpgate.example.yaml

echo 'ghp_token_do_alice' | ./bin/mcpgate cred put --config $CFG --upstream github --principal alice
echo 'ghp_token_do_bob'   | ./bin/mcpgate cred put --config $CFG --upstream github --principal bob
./bin/mcpgate cred ls --config $CFG          # lista (upstream, principal) — SEM segredos
cat secrets/creds.enc                        # cifrado em repouso: nada legível
```

Em runtime, quando **alice** chama uma tool do `github`, o gateway injeta a credencial
de alice no leg sul; **bob** recebe a de bob; um principal **sem** credencial é **negado**
com erro JSON-RPC limpo (`-32003`), e a auditoria registra `upstream_cred` (a referência,
nunca o segredo). A prova ponta a ponta — incluindo o **assert de que o bearer do norte
NÃO aparece na request ao upstream** (upstream HTTP real via `httptest`) — está
automatizada:

```bash
go test ./internal/proxy/    -run 'SouthAuth|PerUser' -v   # injeção, no-passthrough, fail-closed, auditoria
go test ./internal/credstore/ -v                            # vault cifrado em repouso, fail-closed, chave errada
```

## Stack

- **Go 1.25+** — binário único, `CGO_ENABLED=0`.
- SDK oficial [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk) (pacotes `mcp` e `jsonrpc`).
- Config: [`koanf/v2`](https://github.com/knadh/koanf). CLI: [`cobra`](https://github.com/spf13/cobra). Auditoria: `log/slog` (stdlib). Rate limit: [`golang.org/x/time/rate`](https://pkg.go.dev/golang.org/x/time/rate) (in-process).
