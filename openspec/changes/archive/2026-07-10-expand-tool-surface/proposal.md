## Why

The server has broad Tailscale OpenAPI coverage, but many exposed tools are still raw operation-shaped endpoints that are less ergonomic than the richer tool surfaces operators expect. The YawLabs implementation demonstrates useful operator-facing tools for status, local diagnostics, ACL editing, device workflows, DNS, keys, logging, posture, services, users, invites, and webhooks; this change adds comparable curated tools without reducing existing full API parity.

## What Changes

- Add a curated operator tool surface alongside the existing generated `tailscale_<operation>` tools.
- Add tailnet/API health tools such as `tailscale_status` that compose multiple read endpoints into a concise setup/health response.
- Add ACL/policy tools with raw HuJSON preservation and safe update semantics: get policy with ETag, validate policy, preview policy, and update policy with ETag plus confirmation.
- Add device workflow tools with clearer task-oriented names and schemas for list/get, authorize/deauthorize, delete, rename, expire key, routes, tags, IP, posture attributes, and bulk authorization updates.
- Add optional local CLI diagnostic tools gated by explicit configuration, such as local status, ping, netcheck, and local Tailscale version.
- Add additional curated wrappers for existing Admin API domains where they improve ergonomics over generic endpoint names: DNS, invites, keys, logging, posture, services, tailnet settings, users, and webhooks.
- Preserve generated OpenAPI tool coverage, existing resource URIs, grant enforcement, confirmation requirements, and MCP safety hints.
- Document how curated tools relate to raw endpoint tools and which grants/operators need for each surface.
- No breaking changes.

## Capabilities

### New Capabilities

- `operator-tool-surface`: Curated task-oriented MCP tools for Tailscale operators, including composed read-only status tools, safer ACL workflows, ergonomic device/domain wrappers, optional local CLI diagnostics, grant requirements, confirmation rules, and safety hints.

### Modified Capabilities

- `tailscale-api-mcp-mapping`: Clarify that curated tools may wrap or compose existing OpenAPI operations without replacing the canonical generated mapping or changing coverage totals.

## Impact

- Affects MCP registration in `main.go` and/or new internal packages for curated tool groups.
- Affects generic Admin API client usage because curated tools will reuse existing authenticated request helpers rather than duplicate API plumbing.
- Affects local runtime behavior only when local CLI tools are explicitly enabled; those tools shell out to the local `tailscale` binary and must remain disabled by default.
- Affects docs under `docs/` to describe curated tools, raw endpoint tools, grants, confirmations, and local CLI requirements.
- Affects coverage tooling/tests to ensure curated tools do not double-count OpenAPI coverage or remove existing 90/90 parity.
