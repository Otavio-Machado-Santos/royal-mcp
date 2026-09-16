# CLAUDE.md — Royal MCP

## What This Project Is

Royal MCP (`royal-mcp`) is a Rust MCP server that acts as a trust boundary between AI agents and SSH servers. It reads the host inventory from a Royal TS/TSX document (`.rtsz`) via PowerShell, resolves credentials internally, classifies every command through a policy engine, and never exposes secrets to the agent.

## Build & Test

```bash
cargo build --release          # production binary → target/release/royal-mcp
cargo test                     # unit tests (policy, ratelimit)
cargo fmt                      # format before committing
cargo clippy                   # lint before committing
```

Smoke test (requires config.toml with real hosts):
```bash
python3 smoke_mcp.py
```

Diagnostics:
```bash
royal-mcp dump-inventory                    # print visible hosts as JSON
royal-mcp resolve "Host Name"               # test credential resolution (metadata only)
royal-mcp ssh-test "Host Name" uptime       # test SSH execution
royal-mcp file-get "Host Name" /etc/hostname  # test SFTP read
```

## Architecture

```
src/
├── main.rs        — CLI entrypoint (serve, dump-inventory, resolve, ssh-test, file-get, file-put)
├── config.rs      — config.toml deserialization + path resolution
├── model.rs       — HostRaw (internal), HostRecord (internal), HostView (DTO — no credentials)
├── royal.rs       — PowerShell bridge: runs inventory.ps1, parses JSON
├── inventory.rs   — In-memory inventory + scope intersection (allow_host_names / allow_folders)
├── vault.rs       — Credential resolution via persistent pwsh daemon (ADR-0001/0002, Secret zeroize on drop)
├── secret.rs      — Secret type (SecretString wrapper, no Serialize/Display)
├── policy.rs      — Command classification: default-allow, denylist of catastrophic commands only
├── ssh.rs         — SSH/SFTP engine (russh): multiplexed per-host connection pool (ADR-0003), host key pinning, write modes
├── server.rs      — MCP tool implementations (query_hosts, exec, file_put modes, upload chunks, etc.)
├── audit.rs       — Append-only audit log with SHA-256 hash-chain
└── ratelimit.rs   — Per-minute circuit breaker

ps/
├── inventory.ps1    — Emits host inventory as JSON (no secrets)
├── resolve.ps1      — One-shot credential resolution (CLI diagnostics)
└── vault-daemon.ps1 — Persistent vault daemon: opens .rtsz once, serves resolve/reload over stdio (ADR-0001)

docs/                        — Detailed documentation
config.example.toml          — Configuration template (config.toml is gitignored)
.cursor/mcp.json               — Cursor MCP config (team-shared, ${workspaceFolder} paths)
.mcp.example.json            — Claude Code template (.mcp.json is gitignored)
.codex/config.toml.example   — Codex MCP template
AGENTS.md                    — Agent instructions (Codex reads this)
docs/mcp-integration.md      — Full MCP setup guide (Cursor, Claude Code, Codex)
```

## Key Conventions

- **Language:** Rust (edition 2024). PowerShell for Royal TS bridge scripts.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`).
- **Branch strategy:** Never push to `main` directly. Feature branches + PRs.
- **Security invariant:** Credentials never cross the MCP boundary. The `HostView` DTO has no credential field by design.
- **Default-allow (anti-accident):** Commands run by default. Only catastrophic, irreversible commands are denied (disk format, `dd` to a block device, root wipe `rm -rf /`, fork bomb, shutdown/reboot). Pipes, redirection, `sudo`, and interpreters are allowed. The adversarial boundary is host scope + the credential boundary + audit, not command syntax.
- **sudo:** `exec` feeds the vault password to `sudo -S` over the channel stdin (never exposed to the agent), so sudo works without a TTY / without NOPASSWD on password-auth hosts.
- **file_put** modes (ADR-0004): `create` (default, `O_EXCL` create-new), `overwrite`/`append` (under approval, auto-approved when `approval_mode = "agent"`). Binary via `content_b64`; large files via chunked upload (sha256-verified finish). **file_edit** overwrites under approval with TOCTOU re-read.
- **Vault daemon (ADR-0001/0002):** one persistent pwsh child opens the `.rtsz` once and serves credential resolution over stdio; mtime check per resolve triggers reopen, `refresh_inventory` forces it. Respawn on death + one retry on transport failure.
- **SSH pool (ADR-0003):** one multiplexed connection per host (~75s idle TTL, max 8 channels), transparent reconnect on dead connection, one retry with 2s backoff on connect timeout.

## Configuration

`config.toml` (gitignored) controls all operational policy:
- `document_path` — path to the `.rtsz` file
- `scope.allow_host_names` / `scope.allow_folders` — which hosts the agent can see
- `approval_mode` — `"elicitation"` or `"agent"`
- `[limits]` — timeouts, output caps, rate limit
- `[files]` — path denylist, size caps

Override config path via env: `ROYAL_MCP_CONFIG=/path/to/config.toml`

## Important Notes for Development

- `config.toml` and `.mcp.json` are gitignored — they contain real host names and machine-specific paths. Use `config.example.toml` and `.mcp.example.json` as templates.
- The `audit.log` and `known_hosts` files are runtime artifacts, also gitignored.
- The `Secret` type must never gain `Serialize`, `Display`, or any trait that could expose the value. Only `expose()` provides access, used exclusively by the SSH engine.
- When adding new tools, always audit-log the operation and enforce scope + rate limit.
- The policy engine only maintains a small `CATASTROPHIC` denylist (`src/policy.rs`). Add to it only for genuinely irreversible whole-system destroyers; everything else is allowed by design.
