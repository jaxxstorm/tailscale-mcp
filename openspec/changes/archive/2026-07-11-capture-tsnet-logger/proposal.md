## Why

tsnet startup currently writes plain standard-library log lines next to the MCP server's Zap logs, producing mixed timestamp formats and unstructured messages during startup. Operators need tsnet lifecycle messages to appear in the same logging format as the rest of the server so startup diagnostics are consistent and machine-readable.

## What Changes

- Configure the tsnet server to send its user-visible and backend log output through the existing Zap logger.
- Preserve the current debug behavior by keeping verbose tsnet/backend logs quiet unless debug logging is enabled.
- Keep existing tsnet state, credential, Streamable HTTP, localhost, stdio, and MCP authorization behavior unchanged.
- Avoid adding new MCP tools, resources, prompts, Tailscale Admin API calls, or grant permissions.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `mcp-streamable-http-transport`: tsnet Streamable HTTP startup logs must use the same application logger/output format as other server startup logs.

## Impact

- Affected code: tsnet server construction and logging helpers in `main.go`; focused tests for logger adapter behavior and tsnet server configuration.
- Affected APIs: no Tailscale OpenAPI endpoints are in scope; this is local logging behavior only.
- MCP shape: no new tools, resources, or prompts; existing read-only and mutating MCP operations are unchanged.
- Authorization: no changes to `jaxxstorm.com/cap/mcp` grant names or enforcement.
- Runtime diagnostics: tsnet startup and auth lifecycle messages should no longer appear as raw `log` package output when the application logger is initialized.
