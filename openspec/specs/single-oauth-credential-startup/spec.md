## Purpose

Define startup credential handling around one OAuth-client-backed or federated Tailscale credential.

## Requirements

### Requirement: Startup uses one OAuth or federated credential
The system SHALL require one OAuth-client-backed or federated Tailscale credential for startup instead of separate Admin API and tsnet auth credentials.

#### Scenario: Single credential is configured
- **WHEN** the server starts with the single credential environment variable set
- **THEN** the server uses that credential for Tailscale Admin API clients and tsnet authentication setup

#### Scenario: Single credential is missing
- **WHEN** the server starts without the single credential environment variable
- **THEN** startup fails with an actionable configuration error that names the required variable

#### Scenario: Legacy dual credentials are not required
- **WHEN** the server starts with the single credential environment variable set
- **THEN** `TAILSCALE_API_KEY` and `TS_AUTH_KEY` are not required for startup

### Requirement: Credential type is classified safely
The system SHALL classify the supplied credential for diagnostics without logging secret material or relying on decoded token contents for authorization decisions.

#### Scenario: Credential classification is logged
- **WHEN** the server starts with a credential that can be classified as OAuth-backed, federated, or unknown
- **THEN** logs include the classification and do not include the raw credential value

#### Scenario: Unknown credential type is supplied
- **WHEN** the supplied credential type cannot be classified locally
- **THEN** startup continues to validation and reports Tailscale validation errors if the credential is unusable

### Requirement: Startup validates Admin API access
The system SHALL validate the supplied credential against a low-risk Tailscale Admin API read before accepting requests.

#### Scenario: Credential has required validation scope
- **WHEN** startup validation succeeds
- **THEN** the server proceeds to serve MCP using the configured transport

#### Scenario: Credential lacks required validation scope
- **WHEN** startup validation fails because the credential lacks scope or tailnet access
- **THEN** startup fails with an actionable error describing the missing access and without serving MCP

### Requirement: Admin API calls use the single credential
The system SHALL use the single credential for every typed and generic Tailscale Admin API request made by MCP tools and resources.

#### Scenario: Typed client is created
- **WHEN** the typed Tailscale Admin API client is constructed
- **THEN** it is configured with the single credential

#### Scenario: Generic read API client is created
- **WHEN** the generic Admin API client is constructed
- **THEN** it is configured with the single credential

### Requirement: MCP authorization remains grant-based
The system SHALL keep incoming MCP tool and resource authorization based on `jaxxstorm.com/cap/mcp` grants and SHALL NOT derive MCP user permissions from OAuth or federated credential scopes.

#### Scenario: Tool access is checked
- **WHEN** a user calls an MCP tool
- **THEN** the existing tool grant checks determine access before the tool calls the Tailscale API

#### Scenario: Resource access is checked
- **WHEN** a user reads an MCP resource
- **THEN** the existing resource grant checks determine access before the resource calls the Tailscale API

### Requirement: OpenAPI coverage behavior is unchanged
The system SHALL preserve existing OpenAPI MCP tool/resource mappings, grant permission names, resource URIs, and mutating-operation confirmation tokens while changing only startup credential handling.

#### Scenario: Coverage is regenerated after credential change
- **WHEN** `make coverage` runs after the credential model change
- **THEN** coverage remains fully implemented with the same operation IDs, MCP names or URIs, grant permissions, and confirmation metadata
