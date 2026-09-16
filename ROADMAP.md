# Roadmap

Royal MCP is an early-stage security-sensitive project. The roadmap favors verifiable boundaries over feature count.

## Implemented

- Scoped Royal TS/TSX inventory without credential values in MCP responses
- Persistent credential-resolution daemon with timeout, bounded retry, and sanitized errors
- SSH connection pool with bounded concurrency, idle reaping, and per-stage timeouts
- Persistent TOFU host-key pinning that fails closed
- Default-allow operational command policy with catastrophic-operation denial
- Fixed read-only health check
- SFTP read, create, overwrite, append, and exact text replacement
- Chunked binary uploads with SHA-256 verification
- Sensitive-path and persistence-path write guards
- Append-only audit hash chain and operation rate limiting
- Unit coverage for scope, resolution, policy, audit, uploads, recovery, and concurrency

## Near term

- Add synthetic cross-platform integration fixtures that require no real infrastructure
- Expand Windows/OpenSSH coverage
- Add signed release artifacts and a reproducible release process
- Add property-based tests for command parsing and host resolution
- Document credential rotation and incident-response procedures
- Evaluate a stricter optional policy profile for high-assurance deployments

## Before 1.0

- Complete an independent security review
- Define compatibility guarantees for configuration and tool schemas
- Publish a threat-model checklist and migration guides
- Establish a responsible-disclosure and release cadence based on real maintainer capacity
