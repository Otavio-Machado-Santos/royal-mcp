# 12 · Tools do MCP e integração com o Claude Code

Referência das tools expostas e como plugar no Claude Code. Implementa as Fases
2–5 do `ROADMAP.md`.

---

## 1 · Tools expostas

| Tool | Faixa | O que faz | Aprovação |
|---|---|---|---|
| `query_hosts` | 🟢 | Lista hosts do escopo (filtro por nome e/ou pasta). Sem credencial. | não |
| `get_host` | 🟢 | Detalhe de um host por ID. Sem credencial. | não |
| `list_credentials` | 🟢 | Só os **nomes** de usuário dos hosts do escopo. | não |
| `refresh_inventory` | 🟢 | Recarrega o inventário a partir do `.rtsz`. | não |
| `health_check` | 🟢 | Runbook read-only: `hostname`, `uptime`, `df -h`. | não |
| `exec` | 🟢/🟡/🔴 | Executa um comando. 🟢 direto · 🟡 pede aprovação · 🔴/⚫ recusa. | 🟡 sim |
| `file_get` | 🟢 | Lê arquivo via SFTP (cap + hash no audit). Denylist de paths. | não |
| `file_put` | 🟡 | Cria arquivo **novo** via SFTP. **Nunca sobrescreve.** | sim |
| `file_edit` | 🟡 | Substitui 1 ocorrência exata num arquivo existente. | sim |

Nenhuma tool retorna credencial. O segredo só existe em memória dentro do MCP
(tipo `Secret`, zeroize no drop) e é resolvido sob demanda via `ps/resolve.ps1`.

---

## 2 · Aprovação humana (elicitation)

Comandos 🟡 e escritas (`file_put`/`file_edit`) disparam um **diálogo de
elicitation** do MCP — renderizado pelo harness do Claude Code, **fora** do
contexto do LLM (o modelo não consegue se auto-aprovar). O diálogo mostra host,
endereço, operação e o motivo da faixa amarela. Há um campo `approved` (bool):
só `true` libera a operação.

**Headless = nega por padrão.** Se o cliente não declarar a capability de
elicitation (ex.: `claude -p`, SDK, cron), a faixa 🟡 é **negada** — sem
escrita/restart desatendidos. (Validado: ver doc 10 §5.1.)

---

## 3 · Segurança de transporte

- **Host key pinning (TOFU persistente):** a fingerprint é gravada em
  `known_hosts` na 1ª conexão; divergência depois **recusa** a conexão (anti-MITM).
- **Auth por senha e por chave** (chave privada + passphrase opcional), resolvidas
  do Royal.
- **Timeouts/cap** configuráveis (`[limits]`); **circuit breaker** por minuto.
- **Denylist de paths** para file ops (`[files]`): bloqueia `shadow`, chaves
  privadas, `authorized_keys`, etc., e qualquer `..` (traversal).

---

## 4 · Plugar nos agentes (MCP)

Guia completo: **[mcp-integration.md](mcp-integration.md)** (Cursor, Claude Code, Codex).

**Claude Code** — copie o template e build:

```bash
cp .mcp.example.json .mcp.json
cargo build --release
```

1. Garanta `pwsh_path` no `config.toml`.
2. Abra o Claude Code neste diretório.
3. Confirme o servidor `royal` em `/mcp` ou `claude mcp list`.

**Cursor** — `.cursor/mcp.json` já vem no repo (paths com `${workspaceFolder}`).

### settings.json recomendado

Leitura no `allow` (flui sem prompt); o que muda estado fica no `ask` — o gate
fino é o elicitation do MCP. **Não** ponha as tools mutáveis em "allow always".

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

---

## 5 · Subcomandos de diagnóstico (CLI)

Rodando o binário direto (sem subir o MCP):

```
royal-mcp dump-inventory             # hosts visíveis (JSON)
royal-mcp resolve <host>             # testa o vault (só metadados do segredo)
royal-mcp ssh-test <host> <cmd...>   # executa via SSH (sem passar pela policy)
royal-mcp file-get <host> <path>     # lê arquivo via SFTP
royal-mcp file-put <host> <path> <c> # cria arquivo novo via SFTP
```

> `ssh-test`/`file-put` **ignoram** a policy/aprovação — são ferramentas de
> diagnóstico do operador, não do agente.
