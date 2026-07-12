## Context

`tailscale_list_network_flow_logs` is registered by the generic read API layer. It passes the caller's required `start` and `end` query parameters directly to Tailscale's `GET /tailnet/{tailnet}/logging/network` endpoint, then emits the complete JSON response as one tool result. The endpoint has no upstream pagination or record-limit parameter, while a dense tailnet can produce a result larger than an MCP client's model context.

## Goals / Non-Goals

**Goals:**

- Bound each network-flow-log API request and MCP result to a short chronological time window.
- Let callers continue across a larger requested interval without constructing window boundaries themselves.
- Preserve the existing tool name, upstream endpoint, read-only semantics, and `tool:tailscale_list_network_flow_logs` authorization check.
- Return structured JSON that makes a completed versus resumable retrieval unambiguous.

**Non-Goals:**

- Adding pagination support to the Tailscale API or modifying the Tailscale OpenAPI contract.
- Aggregating, summarizing, filtering, or persisting flow logs.
- Changing configuration audit-log retrieval or any mutating operation.
- Guaranteeing a fixed byte size for unusually dense individual time windows.

## Decisions

1. Replace the generic registration for `listNetworkFlowLogs` with a dedicated read-only tool handler.

The generic registrar cannot express conditional inputs or reshape an endpoint response. The dedicated handler will use the existing `readapi.Client`, `withAccess`, and endpoint definition, keeping the request construction, error sanitization, and grant enforcement shared. The endpoint remains represented in coverage metadata. Alternative considered: add special-case pagination hooks to every generic endpoint. This introduces abstraction for one API that has no native pagination.

2. Page by a fixed five-minute time window and return an opaque cursor.

An initial request accepts RFC3339 `start` and `end` values. The handler requests only `[start, min(start + five minutes, end)]`, preserving the API's chronological ordering. If unqueried time remains, the response includes a base64url-encoded cursor containing the next range boundary and original end; a continuation request accepts that cursor instead of `start` and `end`. Alternative considered: limit the returned log array after requesting the full range. It would still download an oversized upstream payload and could lose records at a page boundary.

3. Return a response envelope rather than the upstream object unchanged.

Each successful call returns the upstream `logs` array together with the effective `start`, `end`, and an optional `nextCursor`. This lets MCP clients continue safely without inferring progress from individual log timestamps, which are not guaranteed to be unique. Alternative considered: expose the next start time as a plain argument. An opaque cursor prevents clients from accidentally mixing an original end bound with an incompatible next boundary.

4. Validate all request ranges before calling Tailscale.

Initial requests require valid RFC3339 timestamps with `start` before `end`. Continuation requests require a valid cursor and reject conflicting range arguments. Invalid cursors or ranges return a tool error without an upstream request. The cursor contains no credentials and requires the same grant as the initial request; it is not a capability token.

## Risks / Trade-offs

- [A five-minute interval is still large on an exceptionally busy tailnet] -> The response envelope allows a future smaller configurable interval without changing the continuation model; initial implementation keeps the interface small.
- [The API's boundary inclusivity can repeat a record at adjacent windows] -> Chunk metadata states the exact queried range, and consumers must tolerate a boundary duplicate rather than omit data.
- [Existing clients expect the raw `{ "logs": [...] }` object] -> This is a documented breaking response-shape change; clients must read `logs` from the new envelope and follow `nextCursor`.
- [Opaque cursors are malformed or manually altered] -> Decode and validate their timestamp bounds before any upstream call.

## Migration Plan

1. Deploy the dedicated handler under the existing tool name and grant.
2. Update tool descriptions and usage documentation to describe the envelope and continuation flow.
3. Clients that only inspect one small interval can continue to send `start` and `end` and read `logs`; clients covering longer intervals must call again with `nextCursor` until it is absent.
4. Roll back by restoring the generic endpoint registration if client compatibility outweighs context protection.

## Open Questions

- None.
