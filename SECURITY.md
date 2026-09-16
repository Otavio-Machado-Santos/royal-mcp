# Security policy

Royal MCP sits on a privileged boundary between AI agents, a credential vault, and SSH infrastructure. Security reports are welcome and should not be filed as public issues until a fix is available.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature for this repository. Include the affected version or commit, reproduction steps, expected impact, and any suggested remediation. Do not include real credentials, Royal documents, customer names, hostnames, IP addresses, or production output.

The maintainer will acknowledge a report as soon as practical, validate it, coordinate a fix, and publish an advisory when users need to take action.

## Supported versions

Until the first stable release, only the latest commit on `main` receives security fixes.

## Security assumptions

- The local machine running Royal MCP is trusted.
- The Royal document and runtime configuration are protected by OS permissions.
- Operators configure a narrow host scope and least-privilege SSH accounts.
- The anti-catastrophe command policy is an accident-prevention layer, not a complete shell sandbox.
- MCP clients enforce their own confirmation policy when `approval_mode = "agent"` is used.

See [docs/architecture.md](docs/architecture.md) for the trust model and known limitations.
