# Command policy

Royal MCP uses a **default-allow, anti-catastrophe** command policy. The purpose is to prevent a small set of irreversible accidents while preserving the ability to perform real operational work.

The policy is not a shell sandbox and is not the primary adversarial boundary. The primary controls are host scope, least-privilege remote accounts, credential isolation, host-key verification, approvals, rate limits, and audit.

## Allowed by design

- Ordinary read and diagnostic commands
- Package, service, container, and configuration-management commands
- Pipes, redirection, command chaining, and interpreters
- `sudo`/`doas` when the scoped credential supports it
- Local file removal that is not recognized as a critical filesystem wipe

## Denied before SSH

- Empty commands
- Disk and filesystem formatting tools such as `mkfs*`, `mke2fs`, `fdisk`, `parted`, `wipefs`, `blkdiscard`, and `nvme format`
- Raw block-device writes and destructive tools such as `dd` and `shred`
- Recursive deletion of `/` and critical top-level system directories
- `find ... -delete` against critical targets
- Fork bombs and writes to `/proc/sysrq-trigger`
- Shutdown, reboot, halt, and equivalent service-manager operations
- Stopping, disabling, or masking the SSH service when it would cause remote lockout

Command segments are inspected after common wrappers such as `sudo`, `env`, `nohup`, and `nice`. Quoted executable names and common service-manager forms are normalized before comparison.

## Sudo handling

When a leading `sudo` or `doas` needs password authentication, the final command is rewritten to consume the password from stdin without a TTY. The credential is injected only when the final command contains the expected stdin-consuming form; otherwise no password is written to the channel.

## Optional hardening

Operators that need allowlist semantics should enforce them through the remote SSH account, forced commands, sudoers rules, containers, or another policy gateway. A future optional strict profile is tracked in the roadmap.
