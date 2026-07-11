## ADDED Requirements

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
