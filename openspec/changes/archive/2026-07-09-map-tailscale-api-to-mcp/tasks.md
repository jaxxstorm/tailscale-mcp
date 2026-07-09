## 1. OpenAPI Source and Coverage Model

- [x] 1.1 Decide whether the coverage generator uses a vendored OpenAPI document, an upstream refresh command, or both.
- [x] 1.2 Define a Go coverage record type with operation ID, method, path, API domain, mapping type, MCP name or URI template, grant permission, status, and rationale.
- [x] 1.3 Define allowed mapping statuses such as implemented, gap, excluded, and planned.
- [x] 1.4 Define reviewed exclusion metadata with reason, notes, and optional follow-up.

## 2. MCP Mapping Rules

- [x] 2.1 Implement classification helpers for resource-eligible read operations, parameterized read tools, mutating tools, workflow prompts, and explicit exclusions.
- [x] 2.2 Define tool naming conventions using lower snake case action-object names.
- [x] 2.3 Define resource URI conventions using the `tailscale://` scheme, plural collection names, and entity URI templates.
- [x] 2.4 Define grant permission naming in coverage output for tools and resources under the existing `jaxxstorm.com/cap/mcp` capability model.
- [x] 2.5 Define destructive-operation safety metadata, including exact identifier requirements and optional confirmation fields.

## 3. Coverage Generation

- [x] 3.1 Add a coverage command or package that parses the Tailscale OpenAPI document into operation records.
- [x] 3.2 Generate `coverage/mcp-coverage.json` with one mapping decision per OpenAPI operation.
- [x] 3.3 Generate `coverage/mcp-coverage.md` grouped by API domain and mapping status.
- [x] 3.4 Support `tools/coverage/exclusions.yaml` so intentional omissions are not reported as unexplained gaps.
- [x] 3.5 Support baseline comparison and generate a Markdown diff for new gaps, closed gaps, and changed mappings.

## 4. Current Implementation Inventory

- [x] 4.1 Inventory currently registered tools and resources from the server implementation.
- [x] 4.2 Map existing `get_device_info`, `list_all_devices`, `tailscale://devices`, `tailscale://device`, `tailscale://policy`, and `tailscale://tailnet-settings` entries into coverage metadata.
- [x] 4.3 Mark all other OpenAPI operations as gaps or reviewed exclusions in the initial coverage report.
- [x] 4.4 Create a parity backlog grouped by Tailscale API domain for future endpoint implementation.

## 5. Verification

- [x] 5.1 Add tests that coverage generation emits every OpenAPI operation exactly once.
- [x] 5.2 Add tests that implemented MCP tools/resources have matching coverage records and grant permissions.
- [x] 5.3 Add tests that mutating operations cannot be classified as resources.
- [x] 5.4 Add tests that exclusions require a reason and do not silently hide implemented mappings.
- [x] 5.5 Run `go test ./...` and the coverage generation command.

## 6. Documentation

- [x] 6.1 Document the API-to-MCP mapping rules for operators and contributors.
- [x] 6.2 Document how to refresh coverage, review gaps, update baselines, and add exclusions.
- [x] 6.3 Update README coverage notes to explain that full API parity is tracked through generated MCP coverage reports.
