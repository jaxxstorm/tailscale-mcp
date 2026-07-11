## Why

Each tsnet-backed MCP server currently falls back to the shared `tsnet-main` state directory, so multiple servers can collide on local node state and reuse the wrong identity. Startup should also register build information with Tailscale so nodes are identifiable by the running binary version.

## What Changes

- Configure each tsnet server with an explicit, server-specific state directory instead of the shared default.
- Keep the existing hostname, port, credential, advertised tags, force-login, Streamable HTTP, and stdio compatibility behavior unchanged.
- Register build information with Tailscale during startup before serving MCP over tsnet.
- Avoid adding new MCP tools, resources, prompts, Tailscale Admin API calls, or grant permissions.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `mcp-streamable-http-transport`: tsnet Streamable HTTP startup must use isolated local state and register build information before serving.
- `single-oauth-credential-startup`: startup credential behavior remains single-credential-based while tsnet state and build metadata are configured during startup.

## Impact

- Affected code: tsnet server construction and startup flow in `main.go`; likely tests around startup configuration and credential-to-tsnet configuration.
- Affected APIs: no Tailscale OpenAPI endpoints are in scope; this is local tsnet startup behavior only.
- MCP shape: no new tools, resources, or prompts; existing read-only and mutating MCP operations are unchanged.
- Authorization: no changes to `jaxxstorm.com/cap/mcp` grant names or enforcement.
- Runtime state: operators running multiple instances should get separate tsnet state per configured server identity rather than shared `tsnet-main` state.
