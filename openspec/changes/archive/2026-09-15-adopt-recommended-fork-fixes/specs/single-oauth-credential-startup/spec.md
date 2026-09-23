## MODIFIED Requirements

### Requirement: Startup uses one OAuth or federated credential
The system SHALL require one OAuth-client-backed or federated Tailscale credential for serving startup instead of separate Admin API and tsnet auth credentials. Informational `--version` and `--list-groups` commands SHALL not require credentials or tailnet configuration and SHALL not perform network access.

#### Scenario: Single credential is configured
- **WHEN** the server starts with the single credential environment variable set
- **THEN** it uses that credential for Admin API clients and, when serving on the tailnet, tsnet authentication setup

#### Scenario: Single credential is missing
- **WHEN** the server starts to serve MCP without the single credential environment variable
- **THEN** startup fails with an actionable configuration error naming the required variable

#### Scenario: Legacy dual credentials are not required
- **WHEN** the server starts with the single credential environment variable set
- **THEN** `TAILSCALE_API_KEY` and `TS_AUTH_KEY` are not required for startup

#### Scenario: Informational command runs offline
- **WHEN** `--version` or `--list-groups` is selected without credentials or a tailnet
- **THEN** it prints the requested information and exits successfully without Admin API validation or tsnet initialization

### Requirement: Startup validates Admin API access
The system SHALL validate the supplied credential against the existing low-risk Tailscale Admin API read before accepting requests, using a context deadline of 30 seconds.

#### Scenario: Credential has required validation scope
- **WHEN** startup validation succeeds
- **THEN** the server proceeds to serve MCP using the configured transport

#### Scenario: Credential lacks required validation scope
- **WHEN** startup validation fails because the credential lacks scope or tailnet access
- **THEN** startup fails with an actionable error describing the missing access and without serving MCP

#### Scenario: Validation stalls
- **WHEN** the validation request does not complete within 30 seconds
- **THEN** startup cancels validation and fails without opening MCP listeners

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

## ADDED Requirements

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
