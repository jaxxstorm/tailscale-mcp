## ADDED Requirements

### Requirement: Network flow logs are retrieved in bounded chronological chunks
The system SHALL expose `tailscale_list_network_flow_logs` as a read-only MCP tool that retrieves Tailscale `GET /tailnet/{tailnet}/logging/network` data in chronological windows no longer than five minutes. An initial call MUST provide RFC3339 `start` and `end` timestamps with `start` before `end`; it MUST retrieve only the first bounded window of that range.

#### Scenario: Initial request returns the first chunk
- **WHEN** an authorized caller provides a valid network-flow-log `start` and `end` interval longer than five minutes
- **THEN** the tool calls the Tailscale endpoint only for the first five minutes and returns that window's logs

#### Scenario: Short interval is retrieved once
- **WHEN** an authorized caller provides a valid interval no longer than five minutes
- **THEN** the tool calls the Tailscale endpoint for the complete interval and does not require a continuation

#### Scenario: Invalid initial range is rejected
- **WHEN** a caller omits either range timestamp, provides an invalid timestamp, or provides an end that is not after start
- **THEN** the tool returns an input error without calling the Tailscale API

### Requirement: Network flow log chunks support opaque continuation
The system SHALL return each successful network-flow-log result as structured JSON containing `logs`, the effective chunk `start` and `end`, and `nextCursor` when unqueried time remains. The cursor SHALL encode continuation state opaquely; a continuation call MUST accept the cursor without requiring new range timestamps and retrieve the next chronological window from the original interval.

#### Scenario: A response has more chunks
- **WHEN** an initial or continuation request leaves time remaining in its requested interval
- **THEN** the response includes a non-empty `nextCursor` for the next chronological chunk

#### Scenario: A response completes the requested interval
- **WHEN** the returned chunk reaches the requested end timestamp
- **THEN** the response omits `nextCursor` or returns it as null

#### Scenario: A caller continues with a cursor
- **WHEN** an authorized caller supplies a valid `nextCursor`
- **THEN** the tool queries the next bounded window and returns its logs and any further continuation cursor

#### Scenario: A cursor is invalid or conflicts with a range
- **WHEN** a caller supplies a malformed cursor or combines a cursor with start or end timestamps
- **THEN** the tool returns an input error without calling the Tailscale API

### Requirement: Network flow log chunking preserves read authorization
The system SHALL require the existing `tool:tailscale_list_network_flow_logs` grant before validating a continuation or calling the network-flow-log endpoint. The chunking interface SHALL remain read-only and SHALL not introduce a new tool grant, resource, prompt, or mutating operation.

#### Scenario: Unauthorized caller requests a chunk
- **WHEN** a caller without the network-flow-log tool grant invokes the tool with an initial range or cursor
- **THEN** the tool returns a permission error without calling the Tailscale API

#### Scenario: Upstream chunk retrieval fails
- **WHEN** Tailscale returns a non-success response for a bounded network-flow-log request
- **THEN** the tool returns the existing sanitized API error and does not return a continuation cursor
