## Why

The project aims to expose the full Tailscale Admin API through MCP, but there is not yet a systematic way to decide whether each OpenAPI operation should become a tool, resource, prompt, or intentional exclusion. A coverage-driven mapping plan is needed before broad implementation so API parity can be tracked, reviewed, and enforced over time.

## What Changes

- Define a classification model for mapping Tailscale OpenAPI operations to MCP tools, resources, prompts, or explicit exclusions.
- Introduce coverage metadata that records operation IDs, HTTP methods, paths, MCP exposure type, grant permission names, implementation status, and rationale.
- Establish coverage gap reporting similar to the `tscli` coverage workflow, including generated inventories, baselines, diffs, and documented exclusions.
- Define MCP naming conventions for generated or hand-written tools and resources.
- Define safety rules for mutating API operations, including explicit tool names, typed inputs, clear descriptions, authorization, and destructive-action safeguards.
- Require documentation updates so operators can discover exposed capabilities and required Tailscale ACL grants.

## Capabilities

### New Capabilities

- `tailscale-api-mcp-mapping`: Covers how Tailscale OpenAPI operations are classified into MCP tools, resources, prompts, or exclusions, and how coverage gaps are tracked.

### Modified Capabilities

None.

## Impact

- Affects future MCP tool, resource, and prompt registration across `main.go` and any refactored packages introduced for API coverage.
- Adds coverage artifacts and likely supporting commands or tests under a `coverage/` or equivalent package/directory.
- Establishes grant naming and documentation requirements for all Tailscale API-backed MCP operations.
- Does not directly expose new Tailscale API operations yet; it creates the contract and plan for implementing them safely.
