## Purpose

Define Streamable HTTP as the primary MCP transport and preserve stdio only as deprecated compatibility.

## Requirements

### Requirement: Streamable HTTP is the primary transport
The system SHALL expose MCP over Streamable HTTP as the primary supported transport for both Tailscale tailnet access and localhost access.

#### Scenario: Server starts with default transport
- **WHEN** the server starts without legacy transport flags
- **THEN** it serves Streamable HTTP MCP requests at `/mcp` on the tsnet listener and localhost listener

#### Scenario: Streamable HTTP endpoint is logged
- **WHEN** Streamable HTTP serving starts
- **THEN** logs identify the `/mcp` endpoint as Streamable HTTP rather than SSE or generic HTTP

### Requirement: Streamable HTTP preserves grant enforcement
The system SHALL apply the same request logging, origin checks, Tailscale identity lookup, and `jaxxstorm.com/cap/mcp` grant enforcement to Streamable HTTP requests before any tool or resource accesses Tailscale data.

#### Scenario: Tailnet Streamable HTTP request is authorized
- **WHEN** a Streamable HTTP request arrives through the tsnet listener
- **THEN** the request passes through the grant middleware before MCP tool or resource handlers execute

#### Scenario: Unauthorized Streamable HTTP request is rejected
- **WHEN** a Streamable HTTP request cannot be associated with a Tailscale user and grants
- **THEN** the server rejects the request before invoking MCP tool or resource handlers

### Requirement: Legacy stdio transport is deprecated but preserved
The system SHALL keep stdio mode available for compatibility while marking it as deprecated in CLI help, runtime logs, and documentation.

#### Scenario: Stdio mode is selected
- **WHEN** the server starts with the stdio flag
- **THEN** it emits a deprecation warning and then serves MCP over stdio

#### Scenario: Operator reads transport documentation
- **WHEN** an operator reviews setup documentation
- **THEN** Streamable HTTP is presented as the recommended transport and stdio is identified as deprecated compatibility

### Requirement: SSE-era guidance is removed from operator documentation
The system SHALL NOT direct new operators to configure SSE as the MCP transport.

#### Scenario: Operator reads README transport guidance
- **WHEN** the README describes remote MCP access
- **THEN** it references Streamable HTTP and the `/mcp` endpoint without recommending SSE setup

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
The system SHALL preserve the existing Streamable HTTP and localhost MCP serving behavior while changing only tsnet state and build metadata setup.

#### Scenario: Server starts with Streamable HTTP
- **WHEN** the server starts without legacy transport flags
- **THEN** it serves Streamable HTTP MCP requests at `/mcp` on the tsnet listener and localhost listener

#### Scenario: MCP authorization is evaluated
- **WHEN** a Streamable HTTP request arrives through the tsnet listener
- **THEN** the request still passes through the existing grant middleware before MCP tool or resource handlers execute

#### Scenario: OpenAPI operation mappings are inspected
- **WHEN** operators inspect MCP tools and resources backed by the Tailscale OpenAPI surface
- **THEN** existing names, grant permissions, read-only and mutating semantics, pagination behavior, and error handling are unchanged

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
