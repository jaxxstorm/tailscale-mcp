## 1. Network Flow Log Tool

- [x] 1.1 Exclude `listNetworkFlowLogs` from generic read-tool registration and register a dedicated read-only `tailscale_list_network_flow_logs` handler with the existing tool grant.
- [x] 1.2 Implement RFC3339 initial-range validation, opaque cursor encode/decode validation, and five-minute chronological window selection.
- [x] 1.3 Call the existing Tailscale network-flow-log endpoint for only the selected window and return the `logs`, effective range, and optional `nextCursor` envelope.

## 2. Verification

- [x] 2.1 Add unit tests for initial short and multi-window requests, continuation requests, malformed or conflicting input, and exact upstream query ranges.
- [x] 2.2 Add MCP registration and authorization tests confirming the tool remains read-only, uses `tool:tailscale_list_network_flow_logs`, and does not call Tailscale when authorization or input validation fails.
- [x] 2.3 Run the relevant Go tests and `go test ./...`.

## 3. Documentation

- [x] 3.1 Document the network-flow-log tool's five-minute chunking, response envelope, and `nextCursor` continuation flow in the operator usage guide.
