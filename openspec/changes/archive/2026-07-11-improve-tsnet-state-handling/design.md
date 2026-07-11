## Context

The HTTP transport starts one `tsnet.Server` using the configured hostname and credential, then serves MCP over the tailnet listener and a localhost listener. The server currently does not set an explicit tsnet state directory, which lets tsnet use its default state location and can cause multiple MCP instances to share `tsnet-main` state.

This change is limited to local tsnet startup behavior. It does not add Tailscale OpenAPI coverage, change existing MCP tools/resources/prompts, or alter grant enforcement.

## Goals / Non-Goals

**Goals:**

- Give each tsnet-backed MCP server a deterministic, server-specific state directory.
- Ensure startup registers build information with Tailscale using the existing binary version metadata.
- Preserve current Streamable HTTP, localhost, stdio, credential, advertised tag, and force-login behavior.
- Keep the change small and testable through isolated helper behavior where practical.

**Non-Goals:**

- Adding a new CLI flag or environment variable for state directory customization.
- Migrating existing local tsnet state directories automatically.
- Changing MCP permission names, authorization checks, tool/resource registrations, or Tailscale Admin API coverage.
- Changing read-only or mutating operation behavior.

## Decisions

1. Derive tsnet state from the configured hostname.

Use the configured `TS_HOSTNAME`/`Hostname` value to set `tsnet.Server.Dir` to a deterministic directory name such as `tsnet-<hostname>`. This matches the server identity operators already configure and avoids forcing a new configuration surface.

Alternative considered: add `TSNET_STATE_DIR`. This would be more flexible but increases configuration and documentation burden before there is a concrete need.

2. Keep state relative to the process working directory.

Use a relative directory name so existing deployment patterns that rely on the current working directory continue to work. This keeps behavior close to tsnet's existing local-state model while avoiding the shared default.

Alternative considered: use an OS config/cache directory. That would be more globally consistent but risks surprising container and service deployments that already manage writable working directories.

3. Register build info during startup before tsnet listens.

Call the Tailscale build info registration hook before `tsServer.Listen` so the local client advertises the binary's build/version metadata as part of normal startup. Use the existing `buildVersion` variable as the source for the application version.

Alternative considered: register after the listener is created. Earlier registration is simpler to reason about and avoids serving before metadata has been installed.

4. Do not change MCP authorization or OpenAPI mappings.

The change affects no Tailscale OpenAPI endpoints. All existing MCP tools and resources keep their current names, read-only/mutating semantics, grant names, pagination behavior, and error handling.

## Risks / Trade-offs

- Existing deployments that relied on shared `tsnet-main` state may need a fresh login or node approval for the new per-hostname state directory. Mitigation: `TSNET_FORCE_LOGIN` already defaults to true and startup continues to use the supplied credential.
- Hostname changes will intentionally create a different state directory. Mitigation: this follows the configured server identity and avoids cross-identity reuse.
- Relative state paths depend on the process working directory. Mitigation: this preserves current deployment expectations and avoids introducing a new state path contract.
