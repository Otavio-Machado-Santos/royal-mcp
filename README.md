# Royal MCP

Royal MCP is a Rust [Model Context Protocol](https://modelcontextprotocol.io/) server that lets AI agents operate SSH hosts from a Royal TS/TSX inventory without exposing credentials to the model.

The server acts as a local trust boundary: it resolves credentials inside its own process, limits which hosts the agent can see, pins SSH host keys, applies anti-accident guardrails, rate-limits operations, and records a tamper-evident audit trail.

> Royal MCP is an independent open-source project and is not affiliated with or endorsed by Royal Apps GmbH.

## Why it exists

Infrastructure teams already keep connection metadata and credentials in Royal TS/TSX. Giving those credentials directly to an AI agent breaks the security boundary; manually copying every command and response prevents useful automation. Royal MCP bridges that gap while keeping credentials outside MCP responses.

## Security boundaries

- **Credential isolation:** MCP responses never contain passwords or private keys. Credential types use non-serializable secret wrappers and are zeroized on drop.
- **Explicit host scope:** an allowlist of host names or Royal folders determines what the agent can discover and access. An empty scope exposes nothing.
- **Host-key verification:** persistent TOFU pinning refuses connections when a known host key changes and fails closed if the pin cannot be saved.
- **Anti-catastrophe policy:** command execution is intentionally default-allow for operational usefulness, but irreversible commands such as disk formatting, block-device writes, root filesystem wipes, fork bombs, shutdown, and reboot are denied before SSH.
- **Controlled file operations:** sensitive paths and persistence locations are blocked; overwrite and append operations require approval.
- **Auditability:** an append-only SHA-256 hash chain records operations, results, and content hashes without logging credentials.
- **Resource controls:** connection and command timeouts, output caps, rate limiting, SSH connection pooling, and bounded SFTP concurrency reduce runaway-agent risk.

This is a privileged operations tool, not a sandbox. Anyone deploying it should use least-privilege SSH accounts, a narrow host scope, backups, and independent monitoring. See [SECURITY.md](SECURITY.md) and [the architecture guide](docs/architecture.md).

## MCP tools

| Tool | Purpose |
|---|---|
| `query_hosts` | List scoped SSH hosts without credentials |
| `get_host` | Read metadata for one scoped host |
| `list_credentials` | List credential/user names only, never secret values |
| `refresh_inventory` | Reload the Royal inventory and credential daemon |
| `exec` | Execute an SSH command subject to scope, policy, limits, and audit |
| `health_check` | Run a fixed read-only diagnostic runbook |
| `file_get` | Read a size-bounded, non-sensitive remote file |
| `file_put` | Create, overwrite, or append a remote file with approval controls |
| `file_edit` | Apply one exact text replacement with TOCTOU protection |
| `upload_*` | Transfer large files in chunks with SHA-256 verification |

See [the complete tool reference](docs/tools-reference.md).

## Requirements

- Rust stable, edition 2024
- PowerShell Core (`pwsh`)
- [`RoyalDocument.PowerShell`](https://www.powershellgallery.com/packages/RoyalDocument.PowerShell)
- A Royal TS/TSX document (`.rtsz`) containing SSH connections

## Quick start

```bash
git clone https://github.com/Otavio-Machado-Santos/royal-mcp.git
cd royal-mcp
cargo build --release
cp config.example.toml config.toml
```

Edit `config.toml` with the path to your `.rtsz` document and a deliberately narrow `[scope]`. Runtime configuration, Royal documents, audit logs, host keys, and credentials are ignored by Git and must never be committed.

Validate inventory parsing without revealing secrets:

```bash
./target/release/royal-mcp dump-inventory
```

Then configure the stdio server in your MCP client. Ready-to-copy examples are available for [Codex, Claude Code, Cursor, and Claude Desktop](docs/mcp-integration.md).

## Configuration principles

- Keep `approval_mode = "elicitation"` when the MCP client supports interactive elicitation.
- Use `approval_mode = "agent"` only when the client cannot render elicitation and its own workflow reliably obtains approval.
- Never use `ALL_HOSTS` or `*` unless exposing every host in the document is intentional.
- Prefer dedicated, least-privilege SSH accounts over administrator/root credentials.
- Treat `config.toml`, `.rtsz`, `audit.log`, and `known_hosts` as operational data.

## Development

```bash
cargo test --locked
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
```

The unit suite covers host scoping and resolution, catastrophic-command denial, audit-chain behavior, upload integrity, credential-daemon recovery, and concurrency controls. Tests that require real infrastructure are intentionally not included in the public repository.

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Project status

Royal MCP is an early-stage project undergoing active hardening. The credential boundary, scoped inventory, SSH/SFTP operations, audit chain, rate limits, connection pooling, and chunked uploads are implemented. The public roadmap tracks remaining portability, documentation, and security-hardening work.

## License

Licensed under the [Apache License 2.0](LICENSE).
