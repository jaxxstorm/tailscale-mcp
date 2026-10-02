## MODIFIED Requirements

### Requirement: Streamable HTTP is the primary transport
The system SHALL expose MCP over Streamable HTTP as the primary supported transport for Tailscale tailnet access and explicitly enabled localhost access.

#### Scenario: Server starts with default transport
- **WHEN** the server starts without legacy transport flags or local HTTP opt-in
- **THEN** it serves Streamable HTTP MCP requests at `/mcp` on the tsnet listener and does not open a localhost listener

#### Scenario: Local HTTP is enabled
- **WHEN** the server starts in HTTP mode with `--local-http` and an explicit non-empty local grant
- **THEN** it also serves `/mcp` on `127.0.0.1` using the independently configured local port

#### Scenario: Streamable HTTP endpoint is logged
- **WHEN** Streamable HTTP serving starts
- **THEN** logs identify the full `/mcp` URL, scheme, and Streamable HTTP transport rather than SSE or generic HTTP

### Requirement: Streamable HTTP preserves grant enforcement
The system SHALL apply request logging, origin checks, and `jaxxstorm.com/cap/mcp` permission evaluation before any tool or resource accesses Tailscale data. Tailnet requests SHALL obtain identity and grants through Tailscale identity lookup; explicitly enabled loopback requests SHALL use only operator-configured local grants.

#### Scenario: Tailnet Streamable HTTP request is authorized
- **WHEN** a Streamable HTTP request arrives through the tsnet listener
- **THEN** Tailscale identity lookup and capability parsing establish request permissions before tool or resource handlers execute

#### Scenario: Unauthorized Streamable HTTP request is rejected
- **WHEN** a tailnet request lacks a verifiable identity or a caller lacks permission for the requested operation
- **THEN** the request or operation is rejected before any protected backend access

#### Scenario: Local grants cannot authorize a tailnet caller
- **WHEN** local grants are configured and a tailnet caller lacks the required Tailscale capability
- **THEN** local grants do not grant that tailnet caller access

### Requirement: Legacy stdio transport is deprecated but preserved
The system SHALL keep stdio mode available for compatibility while marking it as deprecated in CLI help, runtime logs, and documentation. Stdio SHALL use explicitly configured local grants and SHALL NOT initialize tsnet or require tsnet advertised tags.

#### Scenario: Stdio mode is selected
- **WHEN** the server starts with the stdio flag
- **THEN** it emits a deprecation warning and serves MCP over stdio using the configured local capability context without opening network listeners

#### Scenario: Stdio has no local grants
- **WHEN** a stdio caller invokes a protected operation without configured local grants
- **THEN** the operation is denied before backend access

#### Scenario: Operator reads transport documentation
- **WHEN** an operator reviews setup documentation
- **THEN** Streamable HTTP is recommended and stdio is identified as deprecated compatibility with explicit local grants

### Requirement: MCP transport surface remains unchanged
The system SHALL preserve `/mcp`, existing tool and resource identities, and backend operation semantics while introducing explicit localhost opt-in, optional TLS, and corrected authorization/error handling. It SHALL NOT add named profile URLs or remove curated wrappers.

#### Scenario: Server starts with Streamable HTTP
- **WHEN** the server starts without legacy transport flags
- **THEN** it serves `/mcp` on tsnet and serves the same endpoint on localhost only when explicitly enabled with local grants

#### Scenario: MCP authorization is evaluated
- **WHEN** a Streamable HTTP request arrives through the tsnet listener
- **THEN** it passes through Tailscale grant middleware before accessing Tailscale data

#### Scenario: OpenAPI operation mappings are inspected
- **WHEN** operators inspect MCP tools and resources backed by the Tailscale OpenAPI surface
- **THEN** existing names, exact grant identities, read-only and mutating semantics, pagination, confirmation tokens, and structured API error mapping are preserved

## ADDED Requirements

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
