## Context

The project originally exposed only devices, policy, and tailnet settings, while the generated Tailscale OpenAPI coverage report showed 90 operations with 86 gaps. Full parity requires tools for mutating endpoints as well as read endpoints, so mutating operations are exposed through explicit confirmation-token gates in addition to MCP grants.

The current `main.go` is a single large registration function. Adding dozens of operations directly there would make authorization, coverage mapping, and future mutation support harder to audit. The implementation should introduce a small API client helper and grouped MCP registration functions while preserving the existing stdio and tsnet HTTP behavior.

## Goals / Non-Goals

**Goals:**

- Implement MCP tools for all Tailscale OpenAPI gaps.
- Add resources for stable state collections and entity lookups where resource URIs improve discoverability.
- Preserve existing tools and resources while aligning coverage mappings to the real OpenAPI operation IDs.
- Keep every operation protected by explicit tool/resource grant checks under `jaxxstorm.com/cap/mcp`.
- Regenerate coverage so all OpenAPI operations move to implemented.

**Non-Goals:**

- Replace the current Tailscale API client dependency with generated code.
- Add prompts for multi-step workflows.
- Hide uncovered mutating operations with exclusions.

## Decisions

### Decision: Use a generic Admin API request helper for missing client methods

The implementation will add a small helper that uses the configured API key and tailnet to perform Tailscale Admin API requests by method/path and returns structured JSON. Typed `tailscale.com/client/tailscale/v2` calls can remain for existing endpoints, but broad read coverage should not wait for every endpoint to have a typed Go client wrapper.

Alternative considered: generate a full API client from OpenAPI. That is likely useful later, but it is larger than needed for this read-only coverage wave and would complicate review.

### Decision: Register tools from a table of endpoint definitions

Endpoints will be represented in a table containing operation ID, tool name, description, HTTP method, path template, path/query inputs, grant permission, confirmation token, and optional resource URI template. This keeps naming, authorization, and coverage metadata consistent.

Alternative considered: hand-code every tool handler. That would be straightforward initially but difficult to keep aligned with generated coverage.

### Decision: Use tools as the baseline for all implemented gaps

Every OpenAPI operation gets an MCP tool because tools provide reliable typed inputs and Claude Desktop compatibility. Resources are added selectively for stable state where an operator benefits from browsing or addressable URIs.

Alternative considered: resource-first for all GET endpoints. Parameterized GETs and query-heavy log endpoints are clearer as tools.

### Decision: Guard mutating operations with confirmation tokens

Mutating `POST`, `PUT`, `PATCH`, and `DELETE` operations are exposed as tools, but each requires a `confirm` argument matching the OpenAPI operation ID. This keeps full API parity available while preventing accidental mutation from ordinary tool invocation.

Alternative considered: leave mutating operations as gaps. That preserved safety but failed the full coverage goal.

## Risks / Trade-offs

- Generic request helper bypasses typed client validation -> Use explicit endpoint definitions, MCP grants, and operation-ID confirmation for mutating tools.
- Many new tools overwhelm operators -> Group naming by API domain and document required grants through generated coverage.
- Resource/tool duplication creates confusion -> Tools are canonical for invocation; resources are discoverable views over stable state.
- Tailscale API errors vary by endpoint -> Return structured JSON including status, response body, and operation context without leaking API keys.
- Coverage mapping drifts from registration -> Add tests that compare registered definitions to coverage mappings.

## Migration Plan

1. Add generic Tailscale Admin API request helper and endpoint definition types.
2. Move existing tool/resource registration into grouped helpers without changing behavior.
3. Add endpoint definitions by OpenAPI domain and register tools/resources from those definitions.
4. Update coverage mappings for implemented endpoints.
5. Regenerate coverage and docs.
6. Run `go test ./...`, `make coverage`, and a build.

Rollback is to remove the new endpoint definitions and registration calls; existing device, policy, and settings behavior should remain isolated and recoverable.

## Open Questions

- Should log endpoints expose raw arrays only, or should they add optional filters mirroring query parameters in the first implementation?
- Should resource URI support be limited to collection/entity reads in this wave, leaving logs as tools only?
- Should read-like POST exceptions require separate grant names from normal read tools to make their unusual method visible to operators?
