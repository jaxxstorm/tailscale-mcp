## Context

`tailscale-mcp` currently exposes a small hand-written subset of the Tailscale Admin API as MCP tools and resources. The target state is complete Tailscale OpenAPI coverage, but MCP is not a one-to-one transport mirror: some endpoints are better represented as resources, some as tools, and some as prompts or deliberate exclusions.

The `tscli` project already uses a coverage gap workflow with generated gap reports, baselines, diffs, exclusions, and property coverage. This change adapts that idea for MCP by tracking not only whether an OpenAPI operation is implemented, but also what MCP primitive exposes it and which grant permission protects it.

## Goals / Non-Goals

**Goals:**

- Define a repeatable classification model for every Tailscale OpenAPI operation.
- Keep endpoint coverage complete and discoverable through generated coverage artifacts.
- Define naming conventions for MCP tools, resources, prompts, and grant permissions.
- Make read-only and mutating operations easy to distinguish and authorize.
- Preserve explicit authorization checks for every API-backed MCP operation.
- Support future generated or systematic registration while keeping dangerous operations auditable.

**Non-Goals:**

- Implement every Tailscale OpenAPI operation in this change.
- Replace the Tailscale Admin API client with a generated client.
- Build an MCP proxy that blindly exposes arbitrary HTTP requests.
- Infer user intent for destructive operations without explicit tool calls and typed inputs.

## Decisions

### Decision: Track mapping coverage per OpenAPI operation

Each Tailscale OpenAPI operation will have a coverage record keyed by operation ID, method, and path. The record will include MCP exposure type, MCP name or URI template, grant permission, implementation status, rationale, and any exclusion reason.

Alternative considered: track only implemented tools and resources. That would be simpler, but it would not show missing endpoints or intentional exclusions, making API parity impossible to enforce.

### Decision: Use resources for stable read-addressable state

GET operations that represent stable, addressable data SHOULD be exposed as MCP resources when they have a natural URI, such as `tailscale://devices`, `tailscale://devices/{device_id}`, `tailscale://policy`, or `tailscale://tailnet/settings`.

Alternative considered: expose every GET operation only as a tool. Tools are broadly compatible, but resource URIs make common state discoverable and cacheable by MCP clients.

### Decision: Use tools for parameterized reads and all mutations

All POST, PUT, PATCH, and DELETE operations MUST be exposed as tools, not resources. GET operations SHOULD also have tool coverage when they require non-trivial parameters, filtering, pagination, search behavior, or are important for Claude Desktop compatibility.

Alternative considered: allow parameterized resources for all reads. Parameterized resources are useful, but tools provide clearer input schemas, errors, and compatibility for operator queries.

### Decision: Use prompts only for operator workflows

Prompts are reserved for workflows that combine API operations into guided operator tasks, such as reviewing device posture, investigating a policy issue, or preparing a safe mutation. Prompts MUST NOT be counted as raw endpoint coverage unless they also map to underlying tools/resources.

Alternative considered: generate prompts per API group. That would create noise and duplicate tool descriptions without improving API parity.

### Decision: Require explicit exclusions

An OpenAPI operation may be excluded only with a documented reason, such as unsupported by the Go client, not useful over MCP, deprecated, unsafe without additional product design, or impossible without non-Admin API context.

Alternative considered: leave unimplemented operations as gaps indefinitely. That makes intentional omissions indistinguishable from missed work.

### Decision: Use predictable names

Tool names will use lower snake case and action-object phrasing, such as `list_devices`, `get_device`, `update_device_tags`, or `delete_tailnet_webhook`. Resource URIs will use the `tailscale://` scheme, plural nouns for collections, and path parameters for entities. Grant permissions will align to MCP names and may be represented as `tool:<name>` and `resource:<uri-template>` in generated coverage docs while preserving the existing `jaxxstorm.com/cap/mcp` envelope.

Alternative considered: use OpenAPI operation IDs directly. Operation IDs are useful source metadata, but MCP names should be operator-readable and stable even if upstream naming changes.

### Decision: Make destructive tools hard to call accidentally

Mutating tools MUST use typed schemas, specific descriptions, and operation-specific names. Destructive operations SHOULD require exact identifiers and SHOULD avoid wildcard or bulk defaults. If an upstream operation is unusually risky, the mapping can require an additional confirmation field in the MCP tool schema.

Alternative considered: expose mutations mechanically from OpenAPI. That would maximize speed but weaken operator safety and grant review.

## Coverage Artifacts

The coverage workflow should mirror the useful parts of `tscli/coverage`:

- `coverage/mcp-coverage.json`: generated inventory of all OpenAPI operations and mapping metadata.
- `coverage/mcp-coverage.md`: human-readable coverage report grouped by API domain and MCP primitive.
- `coverage/mcp-coverage-baseline.json`: accepted baseline for coverage comparison.
- `coverage/mcp-coverage-diff.md`: generated diff showing new gaps, closed gaps, and changed mappings.
- `tools/coverage/exclusions.yaml`: reviewed exclusions with reason and owner/rationale.
- `coverage/parity-backlog.md`: prioritized backlog grouped by endpoint domain.

The coverage tooling itself lives under `tools/coverage/` so it remains separate from the runtime MCP server. Generated report artifacts live under `coverage/`. The exact generated filenames can change during implementation, but the system must support generated machine-readable coverage, human-readable reporting, exclusions, and baseline comparison.

## Pagination, Filtering, and Errors

Tools that wrap list endpoints MUST expose pagination and filtering inputs when the upstream API supports them. Resources for collections MAY return default pages or summaries, but MUST document any truncation or pagination behavior. Partial failures MUST be represented in structured JSON where a multi-operation tool is introduced.

API errors MUST preserve useful upstream context while avoiding secret leakage. Authorization failures from Tailscale grants MUST remain distinct from upstream Tailscale API permission errors.

## Risks / Trade-offs

- Coverage records drift from implementation -> Add tests that compare registered MCP operations against coverage metadata.
- Generated mappings become unsafe or noisy -> Keep mutation registration explicit or reviewed, and require rationale for exclusions and destructive operations.
- Resource and tool duplication confuses operators -> Document that resources expose addressable state while tools are preferred for actions and parameterized queries.
- Upstream OpenAPI changes break coverage -> Make coverage generation reproducible and compare against a baseline in CI or a documented verification command.

## Migration Plan

1. Add the mapping metadata format and initial coverage inventory for current tools/resources.
2. Add a generator or verification command that reads the Tailscale OpenAPI document and emits coverage reports.
3. Add exclusions and baseline files for accepted gaps.
4. Incrementally implement endpoint groups until coverage gaps close.
5. Update README/operator docs as new tools and resources are exposed.

Rollback is straightforward because this change initially adds planning artifacts and coverage checks; it does not require changing runtime behavior until implementation begins.

## Open Questions

- Should coverage generation vendor a specific Tailscale OpenAPI document, fetch upstream during generation, or use both with a refresh command?
- Should read endpoints always have both a resource and a tool when practical, or should duplicate exposure be limited to high-value endpoints?
- What confirmation schema should be required for especially destructive operations?
