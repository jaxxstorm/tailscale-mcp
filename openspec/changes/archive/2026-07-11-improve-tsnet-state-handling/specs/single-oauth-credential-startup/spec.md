## ADDED Requirements

### Requirement: Startup credential configures isolated tsnet state
The system SHALL continue using the single startup credential for tsnet authentication while also configuring server-specific tsnet state during startup.

#### Scenario: Single credential starts tsnet
- **WHEN** the server starts with the single credential environment variable set
- **THEN** the server uses that credential for tsnet authentication setup and configures a state directory specific to the configured hostname

#### Scenario: Credential requires advertised tags
- **WHEN** the supplied credential requires advertised tags for tsnet startup
- **THEN** startup still validates advertised tags before attempting to serve MCP

### Requirement: Startup registers build metadata without changing credential behavior
The system SHALL register build metadata during startup without changing Admin API credential validation or MCP authorization behavior.

#### Scenario: Credential validation succeeds
- **WHEN** startup validation succeeds for the configured credential
- **THEN** the server registers build metadata and proceeds to serve MCP using the configured transport

#### Scenario: Credential validation fails
- **WHEN** startup validation fails because the credential lacks scope or tailnet access
- **THEN** startup fails with an actionable error and does not serve MCP

#### Scenario: MCP authorization remains grant-based
- **WHEN** a user calls an MCP tool or reads an MCP resource after startup
- **THEN** the existing `jaxxstorm.com/cap/mcp` grant checks determine access before the operation calls the Tailscale API
