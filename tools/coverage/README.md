# MCP Coverage Tooling

This directory contains repository tooling for tracking Tailscale OpenAPI coverage through MCP tools and resources. It is intentionally separate from the runtime MCP server.

## OpenAPI Source

The coverage generator reads a vendored OpenAPI YAML document from `tools/coverage/tailscale-v2-openapi.yaml` by default. Refreshing that file from upstream should be a deliberate repository update so coverage diffs are reviewable and reproducible.

Refresh the vendored schema with:

```bash
make openapi-refresh
```

## Mapping Rules

- Stable read-only collection or state endpoints can map to `tailscale://` resources.
- Parameterized reads map to typed MCP tools, with optional resource URI metadata when the same state is also addressable.
- All `POST`, `PUT`, `PATCH`, and `DELETE` endpoints map to tools.
- Destructive tools require exact identifiers and can add confirmation metadata before implementation.
- Prompts are workflow helpers and do not count as raw endpoint coverage.
- Exclusions must be recorded in `tools/coverage/exclusions.yaml` with a reason.

## Generate Reports

```bash
go run ./tools/coverage/cmd/mcpcoverage
```

Generated reports are written to `coverage/`:

- `coverage/mcp-coverage.json`: machine-readable operation inventory and mapping decisions
- `coverage/mcp-coverage.md`: human-readable grouped coverage report
- `coverage/mcp-coverage-diff.md`: diff against `coverage/mcp-coverage-baseline.json` when present
- `coverage/parity-backlog.md`: gap backlog grouped by Tailscale API domain

To accept a new baseline, review `coverage/mcp-coverage.json` and copy it to `coverage/mcp-coverage-baseline.json` in a separate intentional change.
