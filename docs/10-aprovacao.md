# Approval modes

Royal MCP supports two approval modes for mutating file operations.

## `elicitation` (default)

The server asks the MCP client to display an approval dialog. If the client cannot render elicitation, rejects the request, or times out, the mutation is denied.

Use this mode whenever the client supports interactive MCP elicitation.

## `agent`

The server assumes that the client or agent obtained explicit user approval before calling the mutating tool. This compatibility mode is necessary for clients that cannot render MCP elicitation, but it moves the confirmation guarantee outside the server.

Use it only with a client workflow you trust to ask at the correct moment.

## What approval does not bypass

Approval never bypasses:

- Host scope
- Rate limits and size limits
- Sensitive-path read/write blocks
- Persistence-path write blocks
- Destination-mode checks
- Upload integrity checks
- TOCTOU verification for exact edits
- Catastrophic-command denial for `exec`

Approval is one layer in the trust model, not authorization to ignore the other controls.
