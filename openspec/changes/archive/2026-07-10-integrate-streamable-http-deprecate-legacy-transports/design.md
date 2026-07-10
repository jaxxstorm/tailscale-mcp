## Context

The server already constructs an `mcp-go` `MCPServer` and serves it with `server.NewStreamableHTTPServer` on `/mcp` through both tsnet and localhost handlers. However, the public interface still treats stdio as a normal mode, the README says stdio is required for Claude Desktop, and SSE-era wording remains in user-facing documentation. Operators need Streamable HTTP to be clearly documented and logged as the primary transport while legacy modes remain available during a deprecation window.

The transport change must not affect Tailscale OpenAPI coverage, MCP tool/resource names, resource URIs, grant permission names, or mutating-operation confirmation tokens. Transport handlers must continue to wrap Streamable HTTP requests with origin checks, request logging, and Tailscale grant middleware before MCP handlers can call tools or resources.

## Goals / Non-Goals

**Goals:**

- Make Streamable HTTP the default and recommended MCP transport over both the tailnet listener and localhost listener.
- Keep `/mcp` as the canonical Streamable HTTP endpoint.
- Deprecate stdio mode in CLI help, runtime logs, and docs while preserving compatibility for this change.
- Remove or update SSE-era documentation so operators do not configure new clients against obsolete transport guidance.
- Preserve complete Tailscale OpenAPI MCP coverage and all existing grant enforcement semantics.
- Add verification that Streamable HTTP setup continues to protect MCP traffic with middleware.

**Non-Goals:**

- Removing stdio support entirely.
- Introducing a new MCP transport path besides `/mcp`.
- Changing MCP tool names, resource URIs, grant names, or Admin API endpoint mappings.
- Changing mutating-operation confirmation behavior.
- Adding prompts or transport-specific Tailscale API behavior.

## Decisions

### Decision: Keep `/mcp` as the canonical Streamable HTTP endpoint

The implementation will keep the current `/mcp` path and make documentation, logs, and CLI help explicitly identify it as Streamable HTTP. This avoids breaking existing clients already using the modern endpoint while still clarifying the intended integration path.

Alternative considered: introduce `/streamable-http` or another explicit path. That would add migration burden without improving MCP client compatibility.

### Decision: Preserve stdio with deprecation warnings

The `--stdio` flag will continue to work, but CLI help and startup logs will describe it as deprecated. Runtime behavior should warn before serving stdio so operators can migrate without immediate breakage.

Alternative considered: remove `--stdio` immediately. That would be a breaking transport change and could strand existing local client setups.

### Decision: Treat SSE as documentation-only legacy cleanup unless code exists

The current runtime uses `NewStreamableHTTPServer`; if no SSE server code remains, implementation should focus on removing stale SSE wording from docs and comments. If SSE-specific code is found during implementation, it should be deprecated or removed from default paths.

Alternative considered: add SSE compatibility wrappers. That conflicts with the goal of moving transport guidance forward.

### Decision: Transport changes do not affect MCP coverage mappings

Coverage metadata remains tied to OpenAPI operation IDs and MCP tool/resource registrations, not transport. The change should not alter coverage counts, tool grant names, resource grant names, or mutating confirmation metadata.

Alternative considered: add transport-specific mapping metadata. That would conflate API coverage with delivery mechanism and make coverage reports harder to interpret.

## Risks / Trade-offs

- Existing stdio users may miss deprecation warnings -> Document migration clearly in README and emit a startup warning when `--stdio` is used.
- Transport wording can drift from runtime behavior -> Add tests or small helpers that make default transport naming and endpoint constants explicit.
- Middleware could be accidentally bypassed while refactoring HTTP setup -> Keep Streamable HTTP handler construction behind the existing logging, origin, and grant middleware chain.
- Some clients may still require stdio -> Deprecate but do not remove stdio in this change.
- Full OpenAPI coverage could appear affected by transport docs -> Run `make coverage` and keep generated coverage at 90/90.

## Migration Plan

1. Introduce clear constants or helper functions for the Streamable HTTP endpoint and transport labels.
2. Update startup logs and CLI help to identify Streamable HTTP as the default and stdio as deprecated.
3. Preserve stdio behavior but emit a deprecation warning when selected.
4. Update README integration steps from stdio-first/SSE-era guidance to Streamable HTTP-first guidance.
5. Verify `go test ./...`, `go build ./...`, and `make coverage`.

Rollback is to revert the documentation/logging/helper changes; existing runtime transport behavior should remain compatible throughout.

## Open Questions

- Should stdio removal be scheduled in a future semver-major change or remain indefinitely as deprecated compatibility?
- Should a future change add a machine-readable transport capabilities resource for clients to discover preferred transport?
