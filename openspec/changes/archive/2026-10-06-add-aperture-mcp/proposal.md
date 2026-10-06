## Why

Operators need to manage Aperture alongside Tailscale through one MCP deployment without mixing their API surfaces. Separate service paths on the same listener make each integration discoverable while retaining the existing transport security and grant enforcement.

## What Changes

- Expose the complete existing Tailscale MCP surface at the preferred explicit `/tailscale/mcp` route while retaining `/mcp` as a backward-compatible alias without a redirect. Both paths use the same Tailscale handler, server, catalog, and session state, with identical grants and transport protections on the tailnet listener and explicitly enabled loopback listener. Preserve existing Tailscale tools, resources, prompts, exact grant names, API mappings, and read/write safeguards; no additional Tailscale Admin OpenAPI operations are in scope.
- Add an independent Aperture MCP server at `/aperture/mcp` on the same listeners and ports. Keep deprecated stdio Tailscale-only.
- Cover all five operations in the Aperture OpenAPI snapshot as typed tools: configuration get, validate, and replace; pricing catalog and exact-model pricing reads. Configuration validation is non-mutating despite using POST. Configuration replacement is mutating and requires explicit confirmation plus the caller's current ETag. No Aperture resources or prompts are introduced.
- Cache the tailnet-only schema from `http://ai/aperture/openapi.json` in `tools/aperture/openapi.json`, with provenance and checksum metadata. Builds, tests, and tool registration use local data, not schema downloads.
- Add operator-configured Aperture base URL support, defaulting to `http://ai/aperture`. Use the MCP deployment's tsnet identity for upstream calls, not Tailscale Admin API credentials or caller identity headers.
- Reuse `jaxxstorm.com/cap/mcp` with distinct `aperture_*` exact tool names and `aperture-config` / `aperture-pricing` groups. Enforce caller-filtered discovery and handler-level checks against separate catalogs. Document that existing broad `*` and `read:*` grants include matching Aperture tools; exact Tailscale names and existing groups do not.

## Capabilities

### New Capabilities
- `aperture-api-mcp`: Cached API contract, identity-aware upstream client, typed tool mappings, config concurrency safeguards, pricing reads, and sanitized errors.

### Modified Capabilities
- `mcp-streamable-http-transport`: Add explicit service-specific paths on shared listeners, retaining `/mcp` as an alias to the same Tailscale handler/server/session state, transport protections, and Tailscale-only stdio.
- `mcp-grant-authorization`: Add Aperture permission names and groups, independent service catalogs, request-specific checks on both routes, and offline metadata discoverability.

## Impact

Routing and startup in `main.go`, endpoint helpers in `transport.go`, server/catalog construction in `catalog.go`, and the tsnet client boundary need updates. A small `internal/aperture` package will own upstream requests and tool mappings. Existing Tailscale clients, credentials, API coverage, and operation semantics remain unchanged.

Existing HTTP client configurations using `/mcp` continue to work; `/tailscale/mcp` is preferred for new configurations. Documentation, endpoint logs, deployment examples, and transport tests must describe both services and the shared-state Tailscale alias; offline group listings describe the two service catalogs. Aperture access requires granting the MCP node the upstream admin role for configuration and explicit `read_pricing: true` for pricing; MCP caller grants remain independently required. No new API keys or forwarded end-user identity are introduced.

The checked-in schema and mocked upstream tests allow development away from the tailnet. Live verification and explicit schema refresh require tailnet access. Aperture unavailability must fail individual Aperture calls without preventing Tailscale serving.
