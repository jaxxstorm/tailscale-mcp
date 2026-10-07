## Purpose

Define Streamable HTTP as the primary MCP transport and preserve stdio only as deprecated compatibility.

## Requirements

Scenarios describing Tailscale serving, aliases, sessions, or protections assume Tailscale MCP is enabled unless explicitly stated otherwise. Disabled Tailscale routes return 404 rather than dispatching to an MCP handler.

### Requirement: Streamable HTTP is the primary transport
The system SHALL expose MCP over Streamable HTTP as the primary supported transport for Tailscale tailnet access and explicitly enabled localhost access. Only when boolean `--tailscale` / `TS_MCP_TAILSCALE` is enabled SHALL it serve the Tailscale MCP at the preferred explicit `/tailscale/mcp` route and backward-compatible `/mcp` alias. Tailscale SHALL default to enabled; bare `--tailscale` or `--tailscale=true` SHALL enable it, and `--tailscale=false` SHALL override `TS_MCP_TAILSCALE=true`. Independently, only when boolean `--aperture` / `TS_MCP_APERTURE` is enabled SHALL it serve the separate Aperture MCP at `/aperture/mcp` on the same listener and port for each enabled listener type. Aperture SHALL default to disabled; `--aperture=true` or bare `--aperture` SHALL enable it, and `--aperture=false` SHALL override `TS_MCP_APERTURE=true`. A configured Aperture URL alone SHALL NOT enable it. When Tailscale is enabled, both Tailscale paths SHALL use the same handler instance, server, catalog, and session state without redirecting, regardless of Aperture enablement.

#### Scenario: Aperture-only HTTP overrides environment-enabled Tailscale
- **WHEN** HTTP serving starts with `TS_MCP_TAILSCALE=true`, `--tailscale=false`, and `--aperture`
- **THEN** only `/aperture/mcp` is served on tailnet and enabled loopback listeners, both `/mcp` and `/tailscale/mcp` return 404, and no Tailscale tools, resources, prompts, Admin API clients, Admin API validation, or Tailscale MCP endpoint URL logs are initialized or emitted
- **AND** shared tsnet transport and identity remain active with the existing enrollment credential and advertised tags where applicable, without requiring `TAILSCALE_TAILNET` or Admin API read scopes

#### Scenario: Both services are disabled for serving
- **WHEN** serving is requested with both Tailscale and Aperture disabled
- **THEN** startup fails with an actionable configuration error before any network access or listener initialization

#### Scenario: Informational commands bypass serving checks
- **WHEN** `--version` or `--list-groups` is requested with both services disabled or with `--stdio --tailscale=false`
- **THEN** it exits successfully offline without serving validation, credentials, or network initialization, and group listing excludes disabled services and always excludes Aperture in stdio

#### Scenario: Server starts with default transport
- **WHEN** the server starts without legacy transport flags, Aperture opt-in, or local HTTP opt-in
- **THEN** it serves `/tailscale/mcp` and the `/mcp` Tailscale alias on the tsnet listener, returns 404 for `/aperture/mcp`, and does not open a localhost listener

#### Scenario: Local HTTP is enabled
- **WHEN** the server starts in HTTP mode with `--aperture`, `--local-http`, and an explicit non-empty local grant
- **THEN** it also serves both service-specific paths and the `/mcp` Tailscale alias on `127.0.0.1` using the independently configured local port

#### Scenario: Streamable HTTP endpoint is logged
- **WHEN** Streamable HTTP serving starts
- **THEN** logs identify each enabled service's full URL, scheme, and Streamable HTTP transport rather than SSE or generic HTTP, and omit endpoint URLs for each disabled service

#### Scenario: Disabled Aperture is unavailable on both listeners
- **WHEN** HTTP serving starts with Aperture disabled and loopback explicitly enabled with local grants
- **THEN** `/aperture/mcp` returns 404 on both tailnet and loopback, even with wildcard or exact Aperture grants, while `/mcp` and `/tailscale/mcp` retain their existing behavior

#### Scenario: Explicit false overrides environment enablement
- **WHEN** HTTP serving starts with `TS_MCP_APERTURE=true`, `--aperture=false`, and a malformed Aperture URL
- **THEN** no Aperture URL validation, upstream client construction, tool registration, route serving, or endpoint URL logging occurs and `/aperture/mcp` returns 404 on both enabled listener types

#### Scenario: URL alone does not enable the route
- **WHEN** HTTP serving starts with `--aperture-url` or `APERTURE_URL` but without Aperture opt-in
- **THEN** Aperture remains disabled and its URL is ignored, even if malformed

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
The system SHALL keep stdio mode available for compatibility while marking it as deprecated in CLI help, runtime logs, and documentation. Stdio serving SHALL require Tailscale enabled and reject `--stdio --tailscale=false` before network access even if Aperture is enabled. Stdio SHALL remain Tailscale-only, use explicitly configured local grants, and SHALL NOT initialize tsnet or the Aperture client or require tsnet advertised tags. It SHALL ignore `--aperture` / `TS_MCP_APERTURE` and `--aperture-url` / `APERTURE_URL`, without validating the URL or registering Aperture tools.

#### Scenario: Stdio cannot serve Aperture instead of Tailscale
- **WHEN** serving is requested with `--stdio --tailscale=false --aperture`
- **THEN** startup fails before Admin API validation, tsnet initialization, or any network access

#### Scenario: Stdio mode is selected
- **WHEN** the server starts with the stdio flag
- **THEN** it emits a deprecation warning and serves the existing Tailscale MCP surface over stdio using the configured local capability context without opening network listeners or registering Aperture tools

#### Scenario: Stdio has no local grants
- **WHEN** a stdio caller invokes a protected operation without configured local grants
- **THEN** the operation is denied before backend access

#### Scenario: Stdio is selected with Aperture opt-in
- **WHEN** the server starts with `--stdio` and `--aperture` or `TS_MCP_APERTURE=true`, even with a malformed Aperture URL
- **THEN** Aperture settings are ignored, no Aperture URL validation or client initialization occurs, and only Tailscale tools are served without HTTP listeners or Aperture endpoint URL logs

#### Scenario: Operator reads transport documentation
- **WHEN** an operator reviews setup documentation
- **THEN** Streamable HTTP is recommended and stdio is identified as deprecated Tailscale-only compatibility with explicit local grants

### Requirement: SSE-era guidance is removed from operator documentation
The system SHALL NOT direct new operators to configure SSE as the MCP transport.

#### Scenario: Operator reads README transport guidance
- **WHEN** the README describes remote MCP access
- **THEN** it references Streamable HTTP, the default `/tailscale/mcp` endpoint, and the opt-in `/aperture/mcp` endpoint without recommending SSE setup

### Requirement: tsnet Streamable HTTP uses server-specific state
The system SHALL configure tsnet Streamable HTTP startup with a deterministic state directory specific to the configured server hostname, rather than relying on the shared tsnet default state directory.

#### Scenario: Server starts with default hostname
- **WHEN** the server starts with the default hostname
- **THEN** the tsnet server uses a state directory specific to that hostname

#### Scenario: Server starts with custom hostname
- **WHEN** the server starts with a custom hostname
- **THEN** the tsnet server uses a different state directory derived from that custom hostname

#### Scenario: Multiple hostnames run on the same host
- **WHEN** two MCP servers start with different configured hostnames on the same machine
- **THEN** their tsnet state directories are different

### Requirement: tsnet startup registers build information
The system SHALL register application build information with Tailscale before serving Streamable HTTP over the tsnet listener.

#### Scenario: Tailnet Streamable HTTP startup initializes tsnet
- **WHEN** the server initializes tsnet for Streamable HTTP
- **THEN** build information for the running MCP server version is registered before the tsnet listener serves requests

### Requirement: MCP transport surface remains unchanged
When Tailscale is enabled, the system SHALL preserve existing Tailscale tool and resource identities and backend operation semantics at the preferred explicit `/tailscale/mcp` route and `/mcp` alias. It SHALL support an independently opt-in Aperture surface at `/aperture/mcp` and preserve explicit localhost opt-in, optional TLS, authorization/error handling, and curated wrappers. It SHALL NOT add arbitrary named profile URLs. While Tailscale is enabled, existing `/mcp` clients SHALL continue to work through a backward-compatible alias to the same Tailscale handler, server, catalog, and session state, without a redirect, whether Aperture is enabled or disabled. When Tailscale is disabled, both aliases SHALL return 404 instead.

#### Scenario: Server starts with Streamable HTTP
- **WHEN** the server starts with Tailscale enabled and without legacy transport flags
- **THEN** it serves `/tailscale/mcp` and the `/mcp` Tailscale alias on tsnet, adding `/aperture/mcp` only with Aperture opt-in, and serves the same enabled routes on localhost only when explicitly enabled with local grants

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

### Requirement: tsnet logs use application logging
The system SHALL route tsnet Streamable HTTP startup and lifecycle logs through the same application logger and output format used by the MCP server.

#### Scenario: tsnet emits user-visible startup logs
- **WHEN** tsnet emits user-visible startup or lifecycle log messages during Streamable HTTP startup
- **THEN** those messages are written through the application logger with the same output format as other server logs

#### Scenario: Server starts without debug logging
- **WHEN** the server starts without debug logging enabled
- **THEN** normal tsnet user-visible logs use the application logger and verbose backend tsnet logs remain quiet

#### Scenario: Server starts with debug logging
- **WHEN** the server starts with debug logging enabled
- **THEN** verbose backend tsnet logs are also routed through the application logger at debug level

#### Scenario: Stdio mode is selected
- **WHEN** the server starts with the stdio flag
- **THEN** stdio behavior remains unchanged and no tsnet logger setup is required

### Requirement: Loopback access is separately enabled and bounded to localhost
The system SHALL require both `--local-http` / `TS_MCP_LOCAL_HTTP` and an explicit non-empty `--local-grants` / `TS_MCP_LOCAL_GRANTS` capability to open loopback HTTP. It SHALL bind only `127.0.0.1`, use `--local-port` / `TS_MCP_LOCAL_PORT` with default 8080, and reject malformed local grant configuration or invalid ports before serving. Documentation SHALL state that all processes able to connect receive the same configured grant.

#### Scenario: Grants alone do not open loopback
- **WHEN** local grants are configured without local HTTP opt-in
- **THEN** no localhost listener is opened

#### Scenario: Local HTTP has no grant
- **WHEN** local HTTP is enabled without a non-empty explicit grant
- **THEN** startup fails with an actionable configuration error before accepting requests

#### Scenario: Local grant JSON is malformed
- **WHEN** local grant configuration has invalid JSON, unknown fields, or invalid field types
- **THEN** startup fails rather than broadening or silently ignoring the grant

#### Scenario: Loopback bind fails
- **WHEN** the configured loopback address is unavailable
- **THEN** startup closes any resources already acquired and exits unsuccessfully without leaving another listener serving

### Requirement: Tailnet HTTPS is optional and never silently downgraded
The system SHALL support `--tls` / `TS_TLS` through Tailscale-issued certificates, default the tailnet port to 443 with TLS and 8080 otherwise, and honor an explicit valid port. Loopback SHALL remain plain HTTP on its independent port. Documentation SHALL identify tailnet HTTPS prerequisites and certificate transparency implications.

#### Scenario: TLS is enabled
- **WHEN** HTTPS is configured and certificates are available
- **THEN** the tailnet endpoint completes HTTPS handshakes with the appropriate Tailscale certificate and logs its HTTPS URL

#### Scenario: TLS setup or certificate issuance fails
- **WHEN** a TLS listener or certificate cannot be established
- **THEN** startup or the handshake fails without falling back to plaintext HTTP

#### Scenario: Tailnet TLS does not change local port
- **WHEN** TLS is enabled with local HTTP opt-in and no explicit ports
- **THEN** tailnet uses 443 and loopback uses plain HTTP on port 8080

### Requirement: Browser origins and loopback hosts are validated independently
The system SHALL accept a present Origin only when it is a single well-formed HTTP(S) serialized origin matching the listener's scheme, hostname, and effective port. It SHALL reject userinfo, paths, queries, fragments, `null`, and multiple origins. Forwarded headers SHALL NOT override the expected scheme or identity. Non-browser requests without Origin SHALL remain supported, subject to normal Host and grant checks. Loopback Host validation SHALL reject non-localhost hosts independently of Origin. Tailnet Host validation SHALL accept only the ready node's full/short DNS name or Tailscale IPs at the configured effective port, independently of Origin, and SHALL reject other aliases before Tailscale identity lookup.

#### Scenario: Prefix-lookalike or different scheme is supplied
- **WHEN** Origin uses a hostname suffix attack or a scheme different from the actual listener
- **THEN** the request is rejected before MCP dispatch

#### Scenario: Equivalent default ports are used
- **WHEN** a valid Origin differs only by hostname case or an explicitly stated default port
- **THEN** it passes the origin check if the normalized origin matches the listener

#### Scenario: Rebinding request omits Origin
- **WHEN** a loopback request uses a non-localhost Host header and no Origin
- **THEN** the full transport stack rejects it before any protected operation executes

#### Scenario: Tailnet request uses an attacker-controlled authority
- **WHEN** a tailnet request uses an unrecognized Host with a matching malicious Origin or no Origin
- **THEN** the server rejects it before identity lookup or MCP dispatch even when the peer would otherwise have valid grants

#### Scenario: Tailnet request uses a canonical node identity
- **WHEN** a request names the ready node's DNS name or Tailscale IP at the configured port
- **THEN** Host validation accepts it subject to the normal Origin and grant checks

### Requirement: Tailnet readiness observes startup cancellation
The system SHALL await tailnet readiness using the startup context before acquiring listeners and SHALL NOT introduce a background readiness wait during TLS setup. Cancellation after SDK initialization SHALL prevent serving and close acquired resources. The system SHALL NOT race `tsnet.Close` against initial `tsnet.Start`, and documentation SHALL distinguish the SDK's non-cancellable initialization from cancellable readiness.

#### Scenario: Startup is canceled while awaiting readiness
- **WHEN** the tailnet readiness wait is blocked and the startup context is canceled after SDK initialization
- **THEN** startup returns promptly, does not bind MCP listeners, and closes the initialized tsnet server

#### Scenario: Startup is canceled during binding
- **WHEN** cancellation occurs between or during listener acquisitions
- **THEN** acquired listeners are closed without starting HTTP serving

### Requirement: HTTP request consumption is bounded without breaking streams
The system SHALL limit request header reads to ten seconds, idle keep-alive connections to 120 seconds, POST bodies to 4 MiB, and body reading to 30 seconds. Body limits SHALL apply before MCP operation dispatch, including for peers without MCP grants. Body-read deadlines SHALL NOT become tool-execution or SSE write deadlines.

#### Scenario: Oversized body is submitted
- **WHEN** a client submits more than 4 MiB using either Content-Length or chunked encoding
- **THEN** the server returns a failure without dispatching the MCP operation or buffering an unbounded body

#### Scenario: Body is sent too slowly
- **WHEN** body reading exceeds 30 seconds
- **THEN** the request fails without dispatching an operation

#### Scenario: Valid stream outlives body deadline
- **WHEN** a valid MCP exchange finishes reading its request body and maintains an SSE stream beyond 30 seconds
- **THEN** the body-read deadline does not terminate that stream

### Requirement: Shutdown coordinates all listeners and preserves failure status
The system SHALL stop both listeners from accepting requests concurrently on SIGINT, SIGTERM, or unexpected serving failure, cancel long-lived request/stream contexts, and drain within a shared ten-second budget. It SHALL report shutdown errors, force-close remaining HTTP connections, and close tsnet after HTTP cleanup. Normal signal shutdown SHALL exit successfully; unexpected serving failures SHALL produce a nonzero exit after cleanup.

#### Scenario: Tailnet has an open stream during shutdown
- **WHEN** shutdown starts with a tailnet SSE stream and an enabled loopback listener
- **THEN** loopback stops accepting new work promptly rather than waiting for the tailnet stream's drain deadline

#### Scenario: Drain deadline expires
- **WHEN** a connection remains after the shutdown budget
- **THEN** it is force-closed and the timeout is reported rather than silently logging successful draining

#### Scenario: Listener fails unexpectedly
- **WHEN** an HTTP Serve call returns an unexpected error
- **THEN** all listeners and tsnet are cleaned up and the process exits unsuccessfully

### Requirement: Service routes isolate MCP surfaces and state
Each enabled service SHALL use its own MCP server, catalog, and Streamable HTTP handler; when Tailscale is enabled, `/mcp` and `/tailscale/mcp` SHALL be aliases of the same Tailscale service and share its handler and state. Tailscale tools, resources, and prompts SHALL be registered only when Tailscale is enabled and only on its surface; Aperture tools SHALL be registered only on the Aperture surface when enabled in HTTP mode. Disabled services SHALL have no registered tools or catalog entries, and disabled Tailscale SHALL have no resources or prompts. Grants SHALL NOT enable disabled services. A session identifier from one service SHALL NOT attach a request to another service's session state or transfer permissions. Both services, when enabled, SHALL share the existing listener lifecycle without adding per-service ports.

#### Scenario: Caller discovers tools on each route
- **WHEN** both services are enabled in HTTP mode and a caller with broad tool grants lists tools on each endpoint
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
