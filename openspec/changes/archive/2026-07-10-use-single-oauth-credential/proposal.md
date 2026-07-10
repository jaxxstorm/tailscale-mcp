## Why

The server currently needs separate credentials for tsnet node authentication and Tailscale Admin API access, which complicates deployment and increases secret handling. Supporting a single OAuth or federated credential with the required scopes lets operators start the MCP server with one credential while preserving least-privilege API access.

## What Changes

- **BREAKING**: Replace the required startup model of `TAILSCALE_API_KEY` plus optional `TS_AUTH_KEY` with a single required OAuth or federated credential.
- Use the single credential for Tailscale Admin API calls and for tsnet authentication where supported by the Tailscale client/runtime.
- Detect or clearly classify whether the credential is OAuth-client-backed or federated, and surface actionable startup errors when the credential is invalid or lacks required scopes.
- Update configuration, CLI help, README, examples, and troubleshooting to remove the dual-credential setup path.
- Preserve all existing MCP tools, resources, grant names, mutating-operation confirmation tokens, and Tailscale OpenAPI coverage behavior.
- Keep read-only and mutating API operation behavior unchanged except for the credential used to authorize upstream Tailscale API requests.

## Capabilities

### New Capabilities

- `single-oauth-credential-startup`: Defines startup configuration and validation for using one OAuth or federated credential for both MCP server identity and Tailscale Admin API access.

### Modified Capabilities

<!-- No existing spec-level capability changes. OpenAPI MCP mapping behavior remains transport- and credential-independent. -->

## Impact

- Affects CLI/env configuration in `main.go`, tsnet server initialization, and Admin API client construction.
- Affects `internal/readapi` client configuration because it currently accepts an API key string.
- Affects README setup, environment variable names, credential guidance, and troubleshooting.
- Does not change MCP tool/resource names, resource URIs, `jaxxstorm.com/cap/mcp` grant enforcement, OpenAPI coverage mappings, or mutating-operation confirmations.
