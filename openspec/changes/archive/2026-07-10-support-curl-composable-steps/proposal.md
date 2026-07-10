## Why

Operators should be able to express workflows as a sequence of ordinary Tailscale API actions that an agent can compose, the same way a shell script can compose `curl` calls. The current broad endpoint coverage provides the API surface, but clients need explicit MCP operation hints so they can safely distinguish read-only, idempotent, and destructive actions before allowing mutations.

## What Changes

- Ensure every Tailscale OpenAPI read endpoint remains exposed as a first-class MCP tool or resource that agents can compose into multi-step workflows.
- Add MCP tool annotations for generated tools so read operations advertise `readOnlyHint`, mutating operations advertise `destructiveHint` when applicable, and idempotent writes advertise `idempotentHint` when applicable.
- Preserve existing explicit `confirm` requirements for mutating tools; hints are additional client-facing metadata, not a replacement for server-side safeguards.
- Preserve `jaxxstorm.com/cap/mcp` grant enforcement for every tool and resource.
- Update coverage validation so every generated tool has the expected safety hints based on the underlying OpenAPI method and operation semantics.
- No Tailscale OpenAPI endpoints are removed or excluded by this change.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `tailscale-api-mcp-mapping`: Add requirements that API-backed MCP tools expose composability and safety metadata, including read-only, destructive, and idempotent hints for client mutation gating.

## Impact

- Affects generated MCP tool registration in `internal/readapi` and any core tools backed by Tailscale API reads.
- Affects coverage tooling and tests under `tools/coverage/` to validate safety hints for all mapped tools.
- Affects operator documentation under `docs/` to explain that agents can compose first-class endpoints and that clients can gate mutations using MCP hints plus existing confirmation inputs.
- Does not change transport behavior, credential handling, OpenAPI coverage totals, grant names, resource URIs, or tool names.
