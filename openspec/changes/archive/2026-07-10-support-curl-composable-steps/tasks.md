## 1. Hint Model

- [x] 1.1 Inspect `mcp-go` tool annotation APIs and current generated/core tool registration paths.
- [x] 1.2 Add endpoint metadata or helper logic for read-only, destructive, and idempotent hint classification.
- [x] 1.3 Define explicit endpoint overrides for read-like POST operations and destructive non-DELETE operations.

## 2. MCP Tool Registration

- [x] 2.1 Apply derived MCP hint annotations to all generated `internal/readapi` endpoint tools.
- [x] 2.2 Apply equivalent read-only hint annotations to core API-backed read tools such as `get_device_info` and `list_all_devices`.
- [x] 2.3 Verify mutating tools still require exact `confirm` values and existing `jaxxstorm.com/cap/mcp` grant checks.

## 3. Coverage And Tests

- [x] 3.1 Extend coverage mapping metadata or validation tests to require safety hints for every API-backed tool mapping.
- [x] 3.2 Add unit tests for hint derivation across GET, ReadLike POST, PUT, DELETE, non-idempotent POST/PATCH, and destructive override cases.
- [x] 3.3 Add registration tests that inspect generated and core tool annotations exposed by MCP server metadata.
- [x] 3.4 Confirm coverage totals remain 90/90 with no gaps, changed tool names, changed resource URIs, or changed grant names.

## 4. Documentation

- [x] 4.1 Update `docs/usage.md` to explain that agents can compose workflows from first-class endpoint tools and resources.
- [x] 4.2 Document how MCP clients can use `readOnlyHint`, `destructiveHint`, and `idempotentHint` to gate mutations.
- [x] 4.3 Document that hints are advisory and server-side grants plus `confirm` remain authoritative.

## 5. Verification

- [x] 5.1 Run `go test ./...`.
- [x] 5.2 Run `go build ./...`.
- [x] 5.3 Run `make coverage` and verify coverage remains 90 total, 90 implemented, 0 gaps, 0 excluded.
- [x] 5.4 Run `openspec status --change "support-curl-composable-steps"` and confirm artifacts are complete.
