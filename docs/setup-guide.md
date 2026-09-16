# Guia de Instalação

Guia passo-a-passo para instalar, configurar e rodar o Royal MCP.

## Pré-requisitos

### 1. Toolchain Rust

Instale via [rustup](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Mínimo: Rust stable com suporte a edition 2024.

### 2. PowerShell Core (pwsh)

O Royal MCP usa `pwsh` para ler o documento Royal TS.

**macOS (Homebrew):**
```bash
brew install powershell
```

**Linux (Ubuntu/Debian):**
```bash
# Veja https://learn.microsoft.com/en-us/powershell/scripting/install/install-ubuntu
sudo apt-get install -y powershell
```

**Windows:**
```powershell
winget install Microsoft.PowerShell
```

### 3. Módulo RoyalDocument.PowerShell

Este módulo PowerShell lê arquivos `.rtsz` programaticamente:

```powershell
pwsh -NoProfile -Command "Install-Module RoyalDocument.PowerShell -Scope CurrentUser"
```

### 4. Documento Royal TS/TSX

Você precisa de um documento `.rtsz` com conexões SSH configuradas. É o mesmo documento que você usa no Royal TS (Windows) ou Royal TSX (macOS).

## Build

```bash
git clone https://github.com/Otavio-Machado-Santos/royal-mcp.git
cd royal-mcp
cargo build --release
```

O binário estará em `./target/release/royal-mcp`.

## Configurar

### config.toml

```bash
cp config.example.toml config.toml
```

Edite `config.toml`:

| Campo | O Que Definir |
|---|---|
| `document_path` | Caminho absoluto para o arquivo `.rtsz` |
| `pwsh_path` | Caminho absoluto para `pwsh` (rode `which pwsh` para descobrir) |
| `scope.allow_host_names` | Nomes exatos dos hosts que o agente deve acessar |
| `scope.allow_folders` | (Opcional) Nomes de pastas/clientes do Royal TS para permitir (substring, case-insensitive) |
| Liberar **todos** os hosts | Coloque `"ALL_HOSTS"` (ou `"*"`) em `allow_host_names` **ou** `allow_folders`. ⚠️ Remove a restrição de escopo e expõe o documento inteiro ao agente — use só quando for intencional |
| `approval_mode` | `"elicitation"` para clientes terminal; `"agent"` para Claude Desktop |

### Integração MCP (agentes)

Siga o guia dedicado: **[mcp-integration.md](mcp-integration.md)** — Cursor, Claude Code, Codex, prompts para o agente instalar e troubleshooting por cliente.

Resumo rápido:

| Cliente | Passo |
|---|---|
| **Cursor** | `.cursor/mcp.json` já vem no repo — só build + `config.toml` |
| **Claude Code** | `cp .mcp.example.json .mcp.json` |
| **Codex** | `mkdir -p .codex && cp .codex/config.toml.example .codex/config.toml` |

## Verificar

### 1. Testar o Inventário

```bash
./target/release/royal-mcp dump-inventory
```

Deve imprimir JSON com os hosts visíveis no seu escopo. Se estiver vazio, verifique:
- O `document_path` está correto?
- O `pwsh` está acessível em `pwsh_path`?
- Os nomes em `scope.allow_host_names` são idênticos aos nomes no Royal TS?

### 2. Testar Resolução de Credencial

```bash
./target/release/royal-mcp resolve "Nome do Host"
```

Imprime apenas metadados (username, tipo de auth, comprimento do segredo) — nunca o segredo em si.

### 3. Testar Conexão SSH

```bash
./target/release/royal-mcp ssh-test "Nome do Host" uptime
```

Resolve a credencial e executa `uptime` via SSH.

### 4. Rodar o Smoke Test

```bash
cargo build
python3 smoke_mcp.py
```

Valida o fluxo do protocolo MCP incluindo o comportamento headless-deny para comandos amarelos.

## Integração

Ver **[mcp-integration.md](mcp-integration.md)** para configuração detalhada de Cursor, Claude Code, Codex e Claude Desktop.

- **Claude Code:** `approval_mode = "elicitation"` (diálogos MCP nativos)
- **Claude Desktop:** `approval_mode = "agent"` (sem elicitation em print mode)

## Troubleshooting

| Sintoma | Causa Provável |
|---|---|
| "script de inventário falhou" | `pwsh_path` errado, ou módulo RoyalDocument.PowerShell não instalado |
| "host não encontrado no escopo" | Nome do host não é idêntico — verifique no Royal TS o nome exato |
| "HOST KEY DIVERGENTE" | Host key mudou (possível MITM, ou servidor foi reconstruído). Delete a linha do `known_hosts` para re-pinar |
| "aprovação indisponível/negada: Client does not support elicitation" | Cliente não declara capability de elicitation. Mude para `approval_mode = "agent"` |
| "limite de N operações/min atingido" | Rate limiter disparado — aguarde ou aumente `max_exec_per_minute` |
