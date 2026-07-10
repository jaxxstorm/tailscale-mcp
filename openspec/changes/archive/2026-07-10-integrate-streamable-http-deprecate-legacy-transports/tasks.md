## 1. Transport Defaults

- [x] 1.1 Introduce explicit constants or helpers for the Streamable HTTP transport name and `/mcp` endpoint path.
- [x] 1.2 Update Streamable HTTP server setup to use the shared endpoint constant for tsnet and localhost listeners.
- [x] 1.3 Update startup logs to identify tailnet and localhost `/mcp` listeners as Streamable HTTP.

## 2. Legacy Transport Deprecation

- [x] 2.1 Update CLI help for `--stdio` to mark stdio mode as deprecated compatibility.
- [x] 2.2 Emit a deprecation warning when stdio mode is selected before serving stdio.
- [x] 2.3 Search for SSE-specific runtime code or comments and remove or update stale SSE-era references.

## 3. Middleware And Authorization Preservation

- [x] 3.1 Verify Streamable HTTP requests still pass through logging middleware, origin checks, and Tailscale grant middleware.
- [x] 3.2 Add tests or focused helper coverage for the Streamable HTTP endpoint configuration and middleware chain where practical.
- [x] 3.3 Confirm tool/resource grant names and mutating-operation confirmation behavior remain unchanged.

## 4. Documentation

- [x] 4.1 Update README setup and integration sections to recommend Streamable HTTP over `/mcp` for new clients.
- [x] 4.2 Mark stdio examples as deprecated compatibility rather than the recommended path.
- [x] 4.3 Remove or replace SSE-era wording in docs with Streamable HTTP terminology.
- [x] 4.4 Document that transport changes do not change Tailscale MCP grants, tool names, resource URIs, or coverage semantics.

## 5. Verification

- [x] 5.1 Run `go test ./...`.
- [x] 5.2 Run `go build ./...`.
- [x] 5.3 Run `make coverage` and verify coverage remains 90/90 with no gaps introduced.
- [x] 5.4 Run `openspec status --change "integrate-streamable-http-deprecate-legacy-transports"` and confirm artifacts are complete.
