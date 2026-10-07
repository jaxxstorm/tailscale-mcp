## Purpose

Define startup credential handling around one OAuth-client-backed or federated Tailscale credential.

## Requirements

### Requirement: Startup uses one OAuth or federated credential
The system SHALL require one OAuth-client-backed or federated Tailscale credential for serving startup instead of separate Admin API and tsnet auth credentials. Informational `--version` and `--list-groups` commands SHALL not require credentials or tailnet configuration and SHALL not perform network access.

#### Scenario: Single credential is configured
- **WHEN** the server starts with the single credential environment variable set
- **THEN** it uses that credential for Admin API clients only when Tailscale MCP is enabled and, when serving on the tailnet, tsnet authentication setup even in Aperture-only mode

#### Scenario: Single credential is missing
- **WHEN** the server starts to serve MCP without the single credential environment variable
- **THEN** startup fails with an actionable configuration error naming the required variable

#### Scenario: Legacy dual credentials are not required
- **WHEN** the server starts with the single credential environment variable set
- **THEN** `TAILSCALE_API_KEY` and `TS_AUTH_KEY` are not required for startup

#### Scenario: Informational command runs offline
- **WHEN** `--version` or `--list-groups` is selected without credentials or a tailnet
- **THEN** it prints the requested information and exits successfully without Admin API validation or tsnet initialization

### Requirement: Credential type is classified safely
The system SHALL classify the supplied credential for diagnostics without logging secret material or relying on decoded token contents for authorization decisions.

#### Scenario: Credential classification is logged
- **WHEN** the server starts with a credential that can be classified as OAuth-backed, federated, or unknown
- **THEN** logs include the classification and do not include the raw credential value

#### Scenario: Unknown credential type is supplied
- **WHEN** Tailscale MCP is enabled and the supplied credential type cannot be classified locally
- **THEN** startup continues to validation and reports Tailscale validation errors if the credential is unusable

### Requirement: Startup validates Admin API access
Only when Tailscale MCP is enabled SHALL the system require `TAILSCALE_TAILNET`, construct Admin API clients, and validate the supplied credential against the existing low-risk Tailscale Admin API read before accepting requests, using a context deadline of 30 seconds. This validation SHALL apply to both HTTP and stdio with Tailscale enabled. Aperture-only HTTP SHALL NOT initialize Admin API clients, perform or log Admin API validation, or require Admin API read scopes or `TAILSCALE_TAILNET`. It SHALL still require the existing `TAILSCALE_OAUTH_TOKEN` credential for shared tsnet enrollment and advertised tags where applicable; disabling the Tailscale MCP service SHALL NOT disable tsnet transport or identity.

#### Scenario: Aperture-only startup needs enrollment but not Admin API access
- **WHEN** HTTP serving starts with `--tailscale=false --aperture`, a valid tsnet enrollment credential and required tags, but no `TAILSCALE_TAILNET` or Admin API read scopes
- **THEN** startup can proceed without constructing Admin API clients or performing or logging the tailnet-settings validation read
- **AND** tsnet still uses the configured enrollment credential and tags

#### Scenario: Aperture-only startup lacks enrollment credentials
- **WHEN** HTTP serving starts with `--tailscale=false --aperture` without `TAILSCALE_OAUTH_TOKEN`
- **THEN** startup fails with an actionable enrollment credential configuration error rather than serving credential-free

#### Scenario: Credential has required validation scope
- **WHEN** startup validation succeeds
- **THEN** the server proceeds to serve MCP using the configured transport

#### Scenario: Credential lacks required validation scope
- **WHEN** startup validation fails because the credential lacks scope or tailnet access
- **THEN** startup fails with an actionable error describing the missing access and without serving MCP

#### Scenario: Validation stalls
- **WHEN** the validation request does not complete within 30 seconds
- **THEN** startup cancels validation and fails without opening MCP listeners

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

### Requirement: Startup credential configures isolated tsnet state
The system SHALL continue using the single startup credential for tsnet authentication while configuring server-specific state during tailnet startup. Stdio SHALL NOT initialize tsnet or require its advertised tags. Failures obtaining the configured startup assertion SHALL propagate as startup errors without logging secret material.

#### Scenario: Single credential starts tsnet
- **WHEN** the server starts on the tailnet with the single credential environment variable set
- **THEN** it uses that credential for tsnet authentication setup and configures a state directory specific to the hostname

#### Scenario: Credential requires advertised tags
- **WHEN** tailnet startup uses a credential requiring advertised tags
- **THEN** startup validates advertised tags before attempting to serve MCP

#### Scenario: Stdio does not require tags
- **WHEN** stdio starts with otherwise valid credentials and no advertised tags
- **THEN** missing tsnet tags do not prevent startup and tsnet is not initialized

#### Scenario: Startup assertion file cannot be read
- **WHEN** tsnet configuration cannot obtain its federated assertion from the configured file
- **THEN** startup fails with a sanitized error rather than continuing with an empty assertion

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

### Requirement: Federated assertions can be refreshed through a file
The system SHALL accept federated credential JSON containing `clientId` and exactly one of inline `idToken` or `idTokenFile`. For file-backed credentials, the Admin API federation callback SHALL reread and trim the file on each assertion acquisition. Missing, unreadable, or empty files SHALL return errors without falling back to a previous assertion. Both typed and generic Admin API clients SHALL use this behavior, and token contents SHALL NOT be logged.

#### Scenario: Assertion file is rotated
- **WHEN** an external refresher atomically replaces the token file and the Admin API client next needs an assertion for token exchange
- **THEN** authentication uses the new assertion without restarting the MCP server

#### Scenario: Cached access token remains valid
- **WHEN** the Admin API SDK can reuse a valid access token
- **THEN** file-backed federation does not require a new assertion acquisition for every API request

#### Scenario: Assertion file becomes invalid
- **WHEN** the token file is missing, unreadable, or empty on the next assertion acquisition
- **THEN** authentication fails with a sanitized error rather than using stale assertion contents

#### Scenario: Credential defines ambiguous assertion sources
- **WHEN** federated JSON supplies both `idToken` and `idTokenFile`, or neither
- **THEN** parsing fails with an actionable validation error

#### Scenario: Existing inline credentials are used
- **WHEN** an existing valid inline federated credential is configured
- **THEN** it continues to authenticate without requiring a token file

### Requirement: Federation refresh scope is explicit
The system SHALL initialize tsnet from the current assertion snapshot and SHALL document that file refresh applies to Admin API assertion acquisition, not automatic OIDC issuance or guaranteed tsnet reauthentication refresh. Documentation SHALL require external refreshers to protect the file and replace it atomically.

#### Scenario: Operator configures long-running federation
- **WHEN** an operator follows credential documentation
- **THEN** it distinguishes Admin API token refresh from tsnet startup and explains external token rotation and file protection
