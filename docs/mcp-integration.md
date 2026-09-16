# Integração MCP — Cursor, Claude Code e Codex

Guia para conectar o **Royal MCP** a agentes de IA. Cobre onde cada cliente lê a configuração, como compartilhar com o time e **prompts prontos** para pedir ao próprio agente que instale tudo.

> Pré-requisito: [build e `config.toml`](setup-guide.md) já funcionando (`cargo build --release`, `royal-mcp dump-inventory` OK).

---

## Visão geral

O Royal MCP é um servidor **stdio** (binário local `royal-mcp`). Não há URL remota — cada máquina roda seu próprio processo.

| Variável | Obrigatória | Descrição |
|---|---|---|
| `command` | sim | Caminho para `royal-mcp` (após `cargo build --release`) |
| `ROYAL_MCP_CONFIG` | recomendada | Caminho para `config.toml` (hosts, escopo, políticas) |

O binário sem subcomando já sobe o MCP via stdio (`royal-mcp` ≡ `royal-mcp serve`).

---

## Comparativo por cliente

| Cliente | Arquivo de config | Escopo projeto | Escopo global | Formato | Interpolação de paths |
|---|---|---|---|---|---|
| **Cursor** | `.cursor/mcp.json` | Sim (commitável) | `~/.cursor/mcp.json` | JSON `mcpServers` | `${workspaceFolder}`, `${env:VAR}`, `${userHome}` |
| **Claude Code** | `.mcp.json` (raiz) | Sim (`--scope project`) | `~/.claude.json` (`--scope user`) | JSON `mcpServers` | `${VAR}`, `${VAR:-default}` |
| **Codex** | `.codex/config.toml` | Sim (repo trusted) | `~/.codex/config.toml` | TOML `[mcp_servers.*]` | Paths absolutos ou relativos ao CWD |

**Padrão emergente:** quase todos usam o objeto `mcpServers` em JSON. O Codex é a exceção — usa TOML na seção `[mcp_servers]`.

**O que este repositório fornece:**

| Arquivo | Para quem |
|---|---|
| [`.cursor/mcp.json`](../.cursor/mcp.json) | Cursor (time — paths com `${workspaceFolder}`) |
| [`.mcp.example.json`](../.mcp.example.json) | Claude Code (template; copiar para `.mcp.json`) |
| [`.codex/config.toml.example`](../.codex/config.toml.example) | Codex (copiar trecho para `.codex/config.toml`) |
| [`AGENTS.md`](../AGENTS.md) | Codex (instruções lidas automaticamente pelo agente) |

### Gaps que corrigimos em relação ao padrão

| Antes | Agora |
|---|---|
| Só `.mcp.example.json` na raiz (formato Claude Code) | `.cursor/mcp.json` para Cursor (path correto: `.cursor/`, não raiz) |
| README citava só Claude Code / Claude Desktop | Este guia cobre Cursor + Claude Code + Codex |
| Paths absolutos obrigatórios nos exemplos | Cursor usa `${workspaceFolder}`; Claude Code aceita paths relativos ao repo |
| Sem exemplo Codex | `.codex/config.toml.example` + `AGENTS.md` |
| Sem prompt para agente instalar | Seção [Pedir ao agente](#pedir-ao-seu-agente-que-instale) abaixo |

---

## Cursor

**Docs oficiais:** [cursor.com/docs/mcp](https://cursor.com/docs/mcp)

### Onde configurar

| Escopo | Caminho | Quando usar |
|---|---|---|
| Projeto (time) | `.cursor/mcp.json` | Recomendado — já versionado neste repo |
| Global (pessoal) | `~/.cursor/mcp.json` | Quer o Royal MCP em **todos** os projetos |

Se os dois existirem, o **projeto sobrescreve** o global para entradas com o mesmo nome.

### Setup rápido (neste repo)

1. `cargo build --release`
2. `cp config.example.toml config.toml` e edite (`document_path`, `scope`, etc.)
3. Abra o projeto no Cursor — ele lê [`.cursor/mcp.json`](../.cursor/mcp.json) automaticamente
4. **Settings → MCP** (ou `Cmd+Shift+J` → Features → MCP) → confirme `royal` conectado
5. Se não aparecer: reinicie o Cursor ou **Reload Window**

### Config global (outros projetos)

Adicione em `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "royal": {
      "type": "stdio",
      "command": "/CAMINHO/ABSOLUTO/para/royal-mcp/target/release/royal-mcp",
      "args": [],
      "env": {
        "ROYAL_MCP_CONFIG": "/CAMINHO/ABSOLUTO/para/royal-mcp/config.toml"
      }
    }
  }
}
```

> Global sempre aponta para **um** `config.toml` fixo — todos os workspaces compartilham o mesmo inventário Royal.

### Debug

- **Output → MCP Logs** (`Cmd+Shift+U`)
- Rode o binário manualmente: `./target/release/royal-mcp` (deve ficar aguardando stdio)

---

## Claude Code

**Docs oficiais:** [code.claude.com/docs/en/mcp-quickstart](https://code.claude.com/docs/en/mcp-quickstart)

### Onde configurar

| Escopo | Arquivo | Comando CLI |
|---|---|---|
| `local` (padrão) | `~/.claude.json` (entrada por projeto) | `claude mcp add ...` |
| `project` (time) | `.mcp.json` na raiz | `claude mcp add --scope project ...` |
| `user` (todos projetos) | `~/.claude.json` (top-level) | `claude mcp add --scope user ...` |

### Opção A — arquivo (recomendado para time)

```bash
cp .mcp.example.json .mcp.json
cargo build --release
cp config.example.toml config.toml   # se ainda não tiver
```

O [`.mcp.example.json`](../.mcp.example.json) usa paths **relativos** ao repositório — funcionam quando o Claude Code inicia o servidor a partir da raiz do projeto.

Na primeira sessão, o Claude Code pede **aprovação** dos servidores definidos em `.mcp.json`. Aceite ou use `/mcp` → approve.

### Opção B — CLI

```bash
claude mcp add --scope project royal \
  --env ROYAL_MCP_CONFIG=./config.toml \
  -- ./target/release/royal-mcp
```

Verifique: `claude mcp list` → `royal` com `✓ Connected`.

### Permissões recomendadas (`.claude/settings.json`)

Leitura sem prompt; mutações via elicitation do MCP:

```json
{
  "permissions": {
    "allow": [
      "mcp__royal__query_hosts",
      "mcp__royal__get_host",
      "mcp__royal__list_credentials",
      "mcp__royal__refresh_inventory",
      "mcp__royal__health_check",
      "mcp__royal__file_get"
    ],
    "ask": [
      "mcp__royal__exec",
      "mcp__royal__file_put",
      "mcp__royal__file_edit"
    ]
  }
}
```

Detalhes das tools: [12-tools-e-integracao.md](12-tools-e-integracao.md).

### `approval_mode` no `config.toml`

| Cliente | Valor recomendado |
|---|---|
| Claude Code (terminal) | `"elicitation"` — diálogo MCP nativo |
| Claude Desktop (GUI) | `"agent"` — sem suporte a elicitation em print mode |

---

## Codex (OpenAI)

**Docs oficiais:** [developers.openai.com/codex](https://developers.openai.com/codex/config-sample) · [CLI `codex mcp`](https://developers.openai.com/codex/cli/mcp)

### Onde configurar

| Escopo | Caminho |
|---|---|
| Usuário | `~/.codex/config.toml` |
| Projeto | `.codex/config.toml` (requer projeto **trusted**) |

O Codex **não** lê `.mcp.json` na raiz (diferente de Cursor/Claude Code). Use TOML.

### Opção A — projeto (time)

```bash
mkdir -p .codex
cp .codex/config.toml.example .codex/config.toml
# Edite os paths se o repo não estiver na raiz do workspace
cargo build --release
cp config.example.toml config.toml
```

Marque o projeto como confiável (se o Codex pedir na primeira execução).

### Opção B — CLI global

```bash
codex mcp add royal \
  --env ROYAL_MCP_CONFIG=/caminho/absoluto/para/config.toml \
  -- /caminho/absoluto/para/target/release/royal-mcp
```

Verifique: `codex mcp list` · `codex mcp get royal`

### Exemplo TOML

```toml
[mcp_servers.royal]
enabled = true
command = "./target/release/royal-mcp"
args = []
startup_timeout_sec = 30

[mcp_servers.royal.env]
ROYAL_MCP_CONFIG = "./config.toml"
```

O Codex também lê [`AGENTS.md`](../AGENTS.md) na raiz — útil para o agente saber como instalar sem você repetir os passos.

---

## Pedir ao seu agente que instale

Cole um dos prompts abaixo no chat do agente (Cursor, Claude Code ou Codex). Ajuste o caminho do clone se necessário.

### Prompt universal (qualquer cliente)

```text
Instale e configure o Royal MCP neste ambiente:

1. Clone ou use o repositório royal-mcp já presente
2. cargo build --release
3. Se não existir config.toml, copie de config.example.toml e peça-me os valores de document_path (.rtsz) e scope.allow_host_names
4. Configure o servidor MCP "royal" (stdio) apontando para ./target/release/royal-mcp com ROYAL_MCP_CONFIG=./config.toml
5. Siga docs/mcp-integration.md para o cliente que estou usando (Cursor / Claude Code / Codex)
6. Valide com: ./target/release/royal-mcp dump-inventory
7. Confirme na UI do cliente que o servidor "royal" está conectado e liste as tools disponíveis

Não commite config.toml nem credenciais. Não exponha segredos do Royal TS.
```

### Prompt específico — Cursor

```text
Configure o Royal MCP no Cursor para este workspace:
- Use .cursor/mcp.json com type stdio, command ${workspaceFolder}/target/release/royal-mcp e env ROYAL_MCP_CONFIG=${workspaceFolder}/config.toml
- Se .cursor/mcp.json não existir, crie a partir de .cursor/mcp.json no repo ou docs/mcp-integration.md
- Build: cargo build --release
- config.toml a partir de config.example.toml (pergunte document_path e escopo se faltar)
- Reinicie/reload o Cursor e verifique em Settings → MCP que "royal" conectou
```

### Prompt específico — Claude Code

```text
Configure o Royal MCP no Claude Code com escopo project:
- cp .mcp.example.json .mcp.json (ou: claude mcp add --scope project royal --env ROYAL_MCP_CONFIG=./config.toml -- ./target/release/royal-mcp)
- cargo build --release e config.toml a partir de config.example.toml
- Aprove o servidor em /mcp se pedir
- claude mcp list deve mostrar royal Connected
- Opcional: permissions em .claude/settings.json conforme docs/mcp-integration.md
```

### Prompt específico — Codex

```text
Configure o Royal MCP no Codex:
- cargo build --release
- config.toml a partir de config.example.toml
- Crie .codex/config.toml a partir de .codex/config.toml.example (seção [mcp_servers.royal])
- Ou: codex mcp add royal --env ROYAL_MCP_CONFIG=./config.toml -- ./target/release/royal-mcp
- codex mcp list / codex mcp get royal para validar
- Siga AGENTS.md e docs/mcp-integration.md
```

---

## Checklist pós-instalação

```bash
# 1. Binário
cargo build --release
test -x ./target/release/royal-mcp && echo OK

# 2. Config operacional
test -f ./config.toml && echo OK

# 3. Inventário (sem segredos na saída)
./target/release/royal-mcp dump-inventory | head

# 4. MCP no cliente
# Cursor: Settings → MCP → royal ✓
# Claude Code: claude mcp list
# Codex: codex mcp list
```

Teste no agente: *"Use o servidor royal para listar os hosts no escopo com query_hosts"*.

---

## Troubleshooting

| Sintoma | Cliente | Solução |
|---|---|---|
| Servidor não aparece | Cursor | Arquivo deve ser `.cursor/mcp.json`, não `.mcp.json` na raiz |
| `Pending approval` | Claude Code | `/mcp` → aprovar, ou `claude mcp reset-project-choices` |
| Servidor não carrega | Codex | Projeto precisa ser **trusted**; use `.codex/config.toml`, não JSON |
| `Failed to connect` | Todos | Rode `./target/release/royal-mcp` no terminal; veja o erro |
| Inventário vazio | Todos | `document_path`, `pwsh_path`, `scope.allow_host_names` no `config.toml` |
| `elicitation` negada | Claude Desktop | `approval_mode = "agent"` no `config.toml` |
| Paths quebrados após mover repo | Global Cursor/Codex | Atualize paths absolutos em `~/.cursor/mcp.json` ou `~/.codex/config.toml` |

Mais detalhes: [setup-guide.md](setup-guide.md#troubleshooting).

---

## Referências

- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Cursor MCP](https://cursor.com/docs/mcp)
- [Claude Code MCP](https://code.claude.com/docs/en/mcp-quickstart)
- [Codex config sample](https://developers.openai.com/codex/config-sample)
- [Codex MCP CLI](https://developers.openai.com/codex/cli/mcp)
- [Arquitetura e segurança](architecture.md)
- [Tools MCP](tools-reference.md)
