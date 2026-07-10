## Context

The server now maps the full vendored Tailscale OpenAPI snapshot to MCP tools and resources. This gives agents the same primitive building blocks a human would use with `curl`, but the current tool metadata does not consistently tell MCP clients which calls are read-only, idempotent, or destructive.

The project already has a central `internal/readapi.Endpoint` inventory for generated API-backed tools. That inventory is the right place to derive safety hints because it already records method, operation ID, summary, read-like exceptions, and confirmation requirements. Core hand-written tools should receive equivalent annotations where they expose Tailscale API reads.

## Goals / Non-Goals

**Goals:**

- Preserve first-class MCP access to every mapped Tailscale OpenAPI operation so agents can compose multi-step workflows from ordinary endpoint tools and resources.
- Add MCP tool annotations using `mcp.WithReadOnlyHintAnnotation`, `mcp.WithDestructiveHintAnnotation`, and `mcp.WithIdempotentHintAnnotation`.
- Keep mutating safeguards server-side by preserving operation-specific grants and exact `confirm` values.
- Make hint coverage testable through coverage tooling and unit tests.
- Document how clients can use hints to gate writes while agents compose read and write steps.

**Non-Goals:**

- Adding a separate workflow language, planner, or prompt layer for multi-step operations.
- Changing tool names, resource URIs, grant names, transport behavior, or credential handling.
- Replacing explicit `confirm` inputs with MCP hints.
- Inferring endpoint behavior from token scopes or user grants at runtime.

## Decisions

1. Derive default hints from endpoint metadata.

   Generated tools will use a small helper that converts `Endpoint` metadata into MCP tool options. `GET` and `ReadLike` endpoints will set `readOnlyHint=true`, `destructiveHint=false`, and `idempotentHint=true`. `PUT` and `DELETE` endpoints will set `idempotentHint=true`; `DELETE` endpoints will also set `destructiveHint=true`. `POST` and `PATCH` endpoints default to `readOnlyHint=false`, `destructiveHint=false`, and `idempotentHint=false` unless endpoint metadata overrides them.

   Alternative considered: manually annotate every tool call site. That would be explicit but duplicative and easy to drift from the endpoint inventory.

2. Add endpoint-level overrides for semantic exceptions.

   Some Tailscale operations are encoded as `POST` but behave like reads or validations, such as policy preview and validation endpoints. Existing `ReadLike` metadata will continue to classify those as read-only. If implementation discovers write endpoints whose destructive or idempotent behavior differs from HTTP-method defaults, add explicit fields to `Endpoint` rather than hard-coding operation IDs inside registration logic.

   Alternative considered: infer all behavior from operation ID verbs like `delete`, `set`, `restore`, or `test`. That is brittle and less auditable than structured endpoint metadata.

3. Hints are advisory; grants and confirmations remain authoritative.

   MCP annotations help clients decide when to ask the operator before invoking a tool, but they do not authorize anything. Server-side authorization remains `jaxxstorm.com/cap/mcp`, and mutating tools still require a `confirm` argument exactly matching the OpenAPI operation ID.

   Alternative considered: relying on client-side gating only. That would weaken safety for clients that ignore annotations or invoke tools programmatically.

4. Coverage remains complete and discoverable.

   The coverage report should keep the current operation-to-MCP mapping totals and add validation that each tool mapping has safety hints. Reports can mention the hint classification without changing mapping status, grant names, or operation coverage accounting.

   Alternative considered: treating hint coverage as a separate OpenAPI coverage dimension. That adds complexity without changing whether an endpoint is implemented.

## Risks / Trade-offs

- Incorrect hint classification could cause clients to over-gate safe operations or under-gate risky ones -> Use conservative defaults, keep explicit confirmation for mutations, and add tests for every generated tool classification.
- MCP clients may ignore annotations -> Continue enforcing grants and confirmation tokens on the server.
- HTTP method semantics may not perfectly match Tailscale operation semantics -> Support explicit endpoint metadata overrides and document any exceptions.
- Adding workload metadata to coverage could make reports noisy -> Keep report changes concise and focused on validation failures or per-tool hint fields.

## Migration Plan

1. Add hint derivation helper for generated endpoint tools.
2. Annotate core read tools with read-only hints.
3. Add tests that inspect registered tools or coverage metadata for expected hint fields.
4. Update docs to explain curl-composable endpoint tools and client mutation gating.
5. Run `go test ./...`, `go build ./...`, and `make coverage` to verify no coverage gaps are introduced.

Rollback is to remove the annotations and coverage validation while leaving endpoint mappings, grants, and confirmation behavior unchanged.

## Open Questions

- Which non-DELETE operations should be marked `destructiveHint=true` because they revoke access, suspend users, expire keys, rotate secrets, or otherwise cause irreversible impact?
- Should `DELETE` operations always set both `destructiveHint=true` and `idempotentHint=true`, or should endpoint metadata omit idempotence when the Tailscale API returns errors on repeated deletion?
