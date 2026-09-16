# Architecture and trust model

## Data flow

```text
MCP client
   |
   | stdio / JSON-RPC (host identifiers, commands, file content)
   v
Royal MCP
   |-- scoped inventory view
   |-- policy, approval, limits, and audit
   |-- credential daemon (secret stays in process memory)
   |
   +--> Royal TS/TSX document through RoyalDocument.PowerShell
   +--> SSH/SFTP through russh
```

The public MCP schema exposes host metadata and operation results. It has no field capable of serializing a password or private-key value. Credential material is resolved only after the target host passes scope checks and is supplied directly to the SSH authentication layer.

## Trust boundaries

### Trusted

- The local OS account and machine running the server
- The configured Royal document and PowerShell module
- The operator who defines host scope and approval mode
- The MCP client only to the extent required by the selected approval mode

### Untrusted

- Model-generated commands and file content
- Remote command output
- Network transport before host-key verification
- Host names supplied by the model

Remote output is returned as data and must not be treated as new instructions by the client.

## Controls

1. **Scope before credentials:** only exact IDs, exact names, or unambiguous name matches inside the configured allowlist can reach credential resolution.
2. **Credential isolation:** secret wrappers do not serialize or display secret values and zeroize memory when dropped.
3. **Host-key pinning:** the first observed key is persisted; later divergence or inability to persist a new pin denies the connection.
4. **Anti-catastrophe policy:** the server rejects a narrow set of irreversible operations before opening SSH. It intentionally does not claim to parse or sandbox arbitrary shell syntax.
5. **File controls:** configured patterns deny reads of sensitive paths and writes to sensitive or persistence-oriented locations. Exact-edit operations verify the pre-approved content hash again before writing.
6. **Approvals:** mutating file operations use MCP elicitation when supported, or rely on the client workflow in agent mode.
7. **Resource bounds:** timeouts, output caps, rate limits, bounded channel permits, upload TTLs, and maximum sizes limit runaway behavior.
8. **Audit:** entries include the previous entry hash, forming a tamper-evident chain. Audit files may contain commands and paths and should be protected as sensitive operational data.

## Known limitations

- The command policy is an anti-accident layer, not an adversarial shell sandbox. A scoped account can still perform any operation permitted by its remote OS privileges unless another control denies it.
- Path matching is lexical. Remote symlink behavior can bypass assumptions made from a path string alone; least-privilege accounts and remote filesystem permissions remain essential.
- `approval_mode = "agent"` moves the confirmation guarantee to the MCP client and its operator.
- TOFU detects changes after first contact but cannot authenticate a malicious key accepted during a compromised first connection.
- Royal document security and local endpoint security are outside the MCP protocol boundary.

## Deployment guidance

- Use dedicated non-root SSH identities.
- Scope by the smallest practical host set.
- Protect `config.toml`, the Royal document, `known_hosts`, and `audit.log` with OS permissions.
- Prefer elicitation-capable clients.
- Monitor and back up target systems independently.
- Review the audit chain and rotate credentials after any suspected endpoint compromise.
