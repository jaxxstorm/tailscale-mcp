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
