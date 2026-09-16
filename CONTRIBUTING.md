# Contributing

Thanks for helping improve Royal MCP.

## Before opening a change

- Search existing issues and open a focused issue for substantial behavior changes.
- Never attach real `.rtsz` files, credentials, audit logs, customer names, hostnames, IP addresses, or production output.
- Use synthetic fixtures and names such as `ACME - PROD` in tests and documentation.
- Preserve the credential boundary: secrets must never implement `Serialize`, `Display`, or `Debug` in a form that reveals their value.
- Keep host-scope, host-key, audit, approval, and rate-limit controls fail-closed.

## Local checks

```bash
cargo test --locked
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
```

Pull requests should explain the problem, security impact, behavior change, and validation performed. New behavior should include focused unit tests. Integration evidence must be sanitized before publication.

By submitting a contribution, you agree that it is licensed under Apache-2.0.
