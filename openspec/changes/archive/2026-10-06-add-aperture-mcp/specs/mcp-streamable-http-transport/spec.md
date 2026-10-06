## MODIFIED Requirements

### Requirement: Streamable HTTP is the primary transport
The system SHALL expose MCP over Streamable HTTP as the primary supported transport for Tailscale tailnet access and explicitly enabled localhost access. It SHALL serve the Tailscale MCP at the preferred explicit `/tailscale/mcp` route and backward-compatible `/mcp` alias, and the separate Aperture MCP at `/aperture/mcp`, on the same listener and port for each enabled listener type. Both Tailscale paths SHALL use the same handler instance, server, catalog, and session state without redirecting.

#### Scenario: Server starts with default transport
- **WHEN** the server starts without legacy transport flags or local HTTP opt-in
- **THEN** it serves both service-specific Streamable HTTP paths and the `/mcp` Tailscale alias on the tsnet listener and does not open a localhost listener

#### Scenario: Local HTTP is enabled
- **WHEN** the server starts in HTTP mode with `--local-http` and an explicit non-empty local grant
- **THEN** it also serves both service-specific paths and the `/mcp` Tailscale alias on `127.0.0.1` using the independently configured local port

#### Scenario: Streamable HTTP endpoint is logged
- **WHEN** Streamable HTTP serving starts
- **THEN** logs identify each full service-specific URL, scheme, and Streamable HTTP transport rather than SSE or generic HTTP

### Requirement: Streamable HTTP preserves grant enforcement
The system SHALL apply request logging, origin checks, and `jaxxstorm.com/cap/mcp` permission evaluation before any tool or resource accesses Tailscale or Aperture data. Tailnet requests SHALL obtain identity and grants through Tailscale identity lookup; explicitly enabled loopback requests SHALL use only operator-configured local grants. All paths SHALL retain existing Host validation, body limits, deadlines, TLS behavior, and coordinated shutdown. `/mcp` and `/tailscale/mcp` SHALL have identical grants and transport protections on both listener types.

#### Scenario: Tailnet Streamable HTTP request is authorized
- **WHEN** a Streamable HTTP request arrives at either service through the tsnet listener
- **THEN** Tailscale identity lookup and capability parsing establish request permissions before tool or resource handlers execute

#### Scenario: Unauthorized Streamable HTTP request is rejected
- **WHEN** a tailnet request lacks a verifiable identity or a caller lacks permission for the requested operation
- **THEN** the request or operation is rejected before any protected backend access

#### Scenario: Local grants cannot authorize a tailnet caller
- **WHEN** local grants are configured and a tailnet caller lacks the required Tailscale capability
- **THEN** local grants do not grant that tailnet caller access on either Tailscale alias or the Aperture route

### Requirement: Legacy stdio transport is deprecated but preserved
The system SHALL keep stdio mode available for compatibility while marking it as deprecated in CLI help, runtime logs, and documentation. Stdio SHALL remain Tailscale-only, use explicitly configured local grants, and SHALL NOT initialize tsnet or the Aperture client or require tsnet advertised tags.

#### Scenario: Stdio mode is selected
- **WHEN** the server starts with the stdio flag
- **THEN** it emits a deprecation warning and serves the existing Tailscale MCP surface over stdio using the configured local capability context without opening network listeners or registering Aperture tools

#### Scenario: Stdio has no local grants
- **WHEN** a stdio caller invokes a protected operation without configured local grants
- **THEN** the operation is denied before backend access

#### Scenario: Operator reads transport documentation
- **WHEN** an operator reviews setup documentation
- **THEN** Streamable HTTP is recommended and stdio is identified as deprecated Tailscale-only compatibility with explicit local grants

### Requirement: SSE-era guidance is removed from operator documentation
The system SHALL NOT direct new operators to configure SSE as the MCP transport.

#### Scenario: Operator reads README transport guidance
- **WHEN** the README describes remote MCP access
- **THEN** it references Streamable HTTP and the `/tailscale/mcp` and `/aperture/mcp` endpoints without recommending SSE setup

### Requirement: MCP transport surface remains unchanged
The system SHALL preserve existing Tailscale tool and resource identities and backend operation semantics while adding the preferred explicit `/tailscale/mcp` route and a separate Aperture surface at `/aperture/mcp`. It SHALL preserve explicit localhost opt-in, optional TLS, authorization/error handling, and curated wrappers. It SHALL NOT add arbitrary named profile URLs. Existing `/mcp` clients SHALL continue to work through a backward-compatible alias to the same Tailscale handler, server, catalog, and session state, without a redirect.

#### Scenario: Server starts with Streamable HTTP
- **WHEN** the server starts without legacy transport flags
- **THEN** it serves both service-specific endpoints and the `/mcp` Tailscale alias on tsnet and serves the same endpoints on localhost only when explicitly enabled with local grants

#### Scenario: MCP authorization is evaluated
- **WHEN** a Streamable HTTP request arrives through the tsnet listener
- **THEN** it passes through Tailscale grant middleware before accessing either backend

#### Scenario: OpenAPI operation mappings are inspected
- **WHEN** operators inspect MCP tools and resources backed by the Tailscale OpenAPI surface
- **THEN** existing names, exact grant identities, read-only and mutating semantics, pagination, confirmation tokens, and structured API error mapping are preserved

#### Scenario: Client uses the old route
- **WHEN** an otherwise valid request targets `/mcp` on tailnet or explicitly enabled loopback
- **THEN** it dispatches directly to the same Tailscale handler and server as `/tailscale/mcp`, with identical grants and protections and without a redirect

#### Scenario: Session continues across Tailscale aliases
- **WHEN** a client initializes a Tailscale session on `/mcp` or `/tailscale/mcp` and submits its session identifier to the other Tailscale path on either enabled listener type
- **THEN** the request uses the same Tailscale session state and is authorized using the current request's trusted grants, not permissions from the initializing request

#### Scenario: Tailscale aliases enforce identical protections
- **WHEN** equivalent unauthorized requests or requests violating Host, Origin, or body-limit rules target `/mcp` and `/tailscale/mcp` on either enabled listener type
- **THEN** both paths apply the same rejection rules before protected backend access

## ADDED Requirements

### Requirement: Service routes isolate MCP surfaces and state
Each service SHALL use its own MCP server, catalog, and Streamable HTTP handler; `/mcp` and `/tailscale/mcp` SHALL be aliases of the same Tailscale service and share its handler and state. Tailscale tools, resources, and prompts SHALL be registered only on the Tailscale surface; Aperture tools SHALL be registered only on the Aperture surface. A session identifier from one service SHALL NOT attach a request to another service's session state or transfer permissions. Both services SHALL share the existing listener lifecycle without adding per-service ports.

#### Scenario: Caller discovers tools on each route
- **WHEN** a caller with broad tool grants lists tools on each endpoint
- **THEN** `/mcp` and `/tailscale/mcp` list only Tailscale tools and `/aperture/mcp` lists only Aperture tools

#### Scenario: Caller invokes a tool on the wrong service
- **WHEN** a caller invokes a Tailscale tool through `/aperture/mcp` or an Aperture tool through `/mcp` or `/tailscale/mcp`
- **THEN** it is rejected as unavailable without backend access

#### Scenario: Session identifier crosses service paths
- **WHEN** a client submits a session identifier obtained on either Tailscale alias to Aperture, or from Aperture to either Tailscale alias
- **THEN** no original session state or permissions are accessible and any request processing uses only the target service's server and current trusted grants

#### Scenario: Both services have open streams during shutdown
- **WHEN** shutdown begins with active streams on both services and loopback enabled
- **THEN** all listeners stop accepting work promptly and all streams are canceled and drained within the existing shared shutdown budget
