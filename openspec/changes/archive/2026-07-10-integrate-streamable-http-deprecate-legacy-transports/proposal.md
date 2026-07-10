## Why

MCP clients have moved toward Streamable HTTP as the primary remote transport, while this server still presents legacy stdio and older HTTP/SSE-era behavior in its interface and documentation. Standardizing around Streamable HTTP gives operators a modern default transport over Tailscale while making legacy modes explicitly deprecated instead of implicitly first-class.

## What Changes

- Introduce Streamable HTTP as the primary supported MCP transport for both tailnet and localhost access.
- Keep all Tailscale OpenAPI MCP tools and resources available through Streamable HTTP with the same `jaxxstorm.com/cap/mcp` grant enforcement.
- Deprecate stdio mode and any SSE-era transport documentation or behavior without removing compatibility in this change.
- Update CLI help, logging, README, and transport documentation so Streamable HTTP is the recommended integration path.
- Add deprecation warnings when legacy stdio mode is selected.
- Do not change Tailscale Admin API tool/resource grant names or mutating-operation confirmation requirements.

## Capabilities

### New Capabilities

- `mcp-streamable-http-transport`: Defines Streamable HTTP as the primary MCP transport, including tailnet and localhost endpoints, grant-preserving request handling, and legacy transport deprecation behavior.

### Modified Capabilities

- `tailscale-api-mcp-mapping`: Clarifies that transport changes do not alter MCP tool/resource mapping, grant names, or coverage semantics.

## Impact

- Affects MCP server startup, transport selection, CLI help, runtime logging, and HTTP handler setup in `main.go`.
- Affects README and operator-facing integration guidance.
- Preserves existing MCP capability authorization under `jaxxstorm.com/cap/mcp` for every tool and resource.
- Does not change the Tailscale OpenAPI coverage set, tool names, resource URIs, or Admin API request semantics.
