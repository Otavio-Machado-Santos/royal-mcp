# AGENTS.md — Royal MCP

Instruções para agentes (Codex, Cursor, Claude Code) que trabalham neste repositório.

## O que é este projeto

Servidor MCP em Rust que conecta agentes de IA a hosts SSH via inventário Royal TS/TSX (`.rtsz`), **sem expor credenciais** ao modelo.

## Antes de usar as tools MCP

1. **Build:** `cargo build --release`
2. **Config:** `config.toml` na raiz (copiar de `config.example.toml`). Nunca commitar — contém paths reais e nomes de hosts.
3. **Validar:** `./target/release/royal-mcp dump-inventory`
4. **Integrar o MCP no cliente** — ver [docs/mcp-integration.md](docs/mcp-integration.md)

| Cliente | Arquivo de config MCP |
|---|---|
| Cursor | `.cursor/mcp.json` (já versionado neste repo) |
| Claude Code | `.mcp.json` (copiar de `.mcp.example.json`) |
| Codex | `.codex/config.toml` (copiar de `.codex/config.toml.example`) |

## Instalação MCP (para o agente executar)

Se o usuário pedir para instalar/configurar o MCP:

```
1. cargo build --release
2. Criar config.toml se ausente (config.example.toml → perguntar document_path e scope)
3. Configurar servidor stdio "royal":
   - command: ./target/release/royal-mcp (ou ${workspaceFolder}/target/release/royal-mcp no Cursor)
   - env ROYAL_MCP_CONFIG: ./config.toml (ou path absoluto)
4. Seguir docs/mcp-integration.md para o cliente ativo
5. Validar: dump-inventory + listar tools no cliente
```

## Segurança (invariantes)

- Credenciais **nunca** cruzam a fronteira MCP
- Policy engine é **default-allow anti-acidente**: só comandos catastróficos irreversíveis (formatar disco, `dd` em block device, wipe da raiz, fork bomb, desligar/reiniciar) são bloqueados. A fronteira adversarial é o escopo de host + a fronteira de credencial + o audit, não a sintaxe do comando
- `file_put` só cria arquivos novos; `file_edit` sobrescreve sob aprovação (auto-aprovada em `approval_mode = "agent"`)
- Não commitar: `config.toml`, `.mcp.json` com paths locais, `*.rtsz`, `audit.log`

## Desenvolvimento

```bash
cargo test && cargo fmt && cargo clippy
```

Convenções e arquitetura: [CLAUDE.md](CLAUDE.md) · [docs/architecture.md](docs/architecture.md)
