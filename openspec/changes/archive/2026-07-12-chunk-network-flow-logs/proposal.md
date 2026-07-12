## Why

The network-flow-log tool forwards an entire requested time range and returns every matching record in one MCP result. Busy tailnets can therefore exceed an LLM provider's context limit before the caller can analyze the logs.

## What Changes

- **BREAKING** Change `tailscale_list_network_flow_logs` from an unbounded raw API response to bounded, chronological time-window chunks with an opaque continuation cursor.
- Return the log records for one chunk together with enough metadata for an MCP client to request the next chunk without expanding the response size.
- Keep the operation read-only and continue to retrieve data from Tailscale's `GET /tailnet/{tailnet}/logging/network` endpoint.
- Preserve the existing `tool:tailscale_list_network_flow_logs` grant requirement; no new resources or prompts are introduced.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `tailscale-read-api-mcp`: Network-flow-log retrieval must bound each MCP result and support continuation through the requested time range.

## Impact

- Affected code: generic read API endpoint registration, tool input/output handling, and read API tests.
- Affected API: Tailscale Admin API `GET /tailnet/{tailnet}/logging/network` (`listNetworkFlowLogs`), which remains the only upstream call.
- Affected MCP interface: the existing read-only network-flow-log tool gains chunk and cursor semantics while retaining its current authorization grant.
