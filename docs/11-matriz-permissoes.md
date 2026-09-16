# Permission matrix

| Operation | Scope required | Approval | Additional controls |
|---|---:|---:|---|
| Query host inventory | Yes | No | Metadata only; no credential values |
| Resolve a credential internally | Yes | No | Secret stays inside the process |
| Execute a command | Yes | No server-side prompt | Catastrophic-command policy, rate limit, timeout, output cap, audit |
| Run fixed health check | Yes | No | Fixed read-only command set |
| Read a remote file | Yes | No | Sensitive-path denylist, size cap, audit hash |
| Create a new remote file | Yes | Yes | Destination must not exist, write-path guards, size cap |
| Overwrite or append a file | Yes | Yes | Write-path guards, size cap, audit hash |
| Exact text edit | Yes | Yes | Unique match, UTF-8, pre-write hash revalidation |
| Start/finalize chunked upload | Yes | Yes at start | TTL, size controls, SHA-256 verification, destination mode |
| Abort upload | Upload ID | No | Removes only the managed temporary object |

An empty scope exposes no hosts. `ALL_HOSTS` and `*` are explicit escape hatches and should be avoided in normal deployments.
