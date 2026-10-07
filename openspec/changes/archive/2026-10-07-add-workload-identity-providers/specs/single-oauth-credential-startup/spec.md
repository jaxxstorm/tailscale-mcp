## MODIFIED Requirements

### Requirement: Credential type is classified safely
The system SHALL classify the supplied credential for diagnostics without logging secret material or relying on decoded token contents for authorization decisions. Valid explicit provider configurations SHALL classify as federated, including when JSON omits `type`. Provider configuration validation SHALL reject unsupported or ambiguous sources before provider I/O and SHALL NOT echo credentials or raw provider responses.

#### Scenario: Credential classification is logged
- **WHEN** the server starts with a credential that can be classified as OAuth-backed, federated, or unknown
- **THEN** logs include the classification and do not include the raw credential value

#### Scenario: Unknown credential type is supplied
- **WHEN** Tailscale MCP is enabled and the supplied credential type cannot be classified locally
- **THEN** startup continues to validation and reports Tailscale validation errors if the credential is unusable

#### Scenario: Provider credential is classified
- **WHEN** valid JSON contains a client ID, audience, and supported provider without an explicit type
- **THEN** it is treated as federated without logging tokens or acquiring an assertion during parsing

### Requirement: Startup validates Admin API access
Only when Tailscale MCP is enabled SHALL the system require `TAILSCALE_TAILNET`, construct Admin API clients, and validate the supplied credential against the existing low-risk Tailscale Admin API read before accepting requests, using a context deadline of 30 seconds. Provider acquisition, token exchange, and the validation read SHALL share that deadline. This validation SHALL apply to both HTTP and stdio with Tailscale enabled. Aperture-only HTTP SHALL NOT initialize Admin API clients, perform or log Admin API validation, or require Admin API read scopes or `TAILSCALE_TAILNET`. It SHALL still require the existing `TAILSCALE_OAUTH_TOKEN` credential for shared tsnet enrollment and advertised tags where applicable; disabling the Tailscale MCP service SHALL NOT disable tsnet transport or identity.

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
- **WHEN** provider acquisition, token exchange, or the validation request does not complete within the shared 30-second deadline
- **THEN** startup cancels the authentication/validation work and fails without opening MCP listeners

### Requirement: Admin API calls use the single credential
The system SHALL use the single credential for every typed and generic Tailscale Admin API request made by MCP tools and resources. Both clients SHALL acquire provider assertions under the initiating request context when their cached access token requires refresh, using a fresh SDK federation source to avoid stale SDK assertion caching. Valid cached access tokens SHALL remain reusable without reacquiring an assertion for each request. Refresh failures SHALL fail the protected request without replaying mutations or falling back to another identity.

#### Scenario: Typed client is created
- **WHEN** the typed Tailscale Admin API client is constructed
- **THEN** it is configured with the single credential

#### Scenario: Generic read API client is created
- **WHEN** the generic Admin API client is constructed
- **THEN** it is configured with the single credential

#### Scenario: Provider-backed access token expires
- **WHEN** either client needs a new access token
- **THEN** it acquires a current assertion from the configured provider and exchanges it using the caller context rather than a stale assertion or detached background request

#### Scenario: Refresh contention is canceled
- **WHEN** a request waiting for the client's in-progress refresh is canceled
- **THEN** it returns cancellation without waiting indefinitely or sending its protected API request

### Requirement: Startup credential configures isolated tsnet state
The system SHALL continue using the single startup credential for tsnet authentication while configuring server-specific state during tailnet startup. Stdio SHALL NOT initialize tsnet or require its advertised tags. Failures obtaining the configured startup assertion SHALL propagate as startup errors without logging secret material. Federated HTTP startup SHALL acquire its assertion before `tsnet.Start()` under the startup context and a maximum 30-second acquisition budget, and SHALL configure only `ClientID` and the acquired `IDToken`, not tsnet's competing `Audience` acquisition selector. Nonempty ambient `TS_AUDIENCE`, `TS_AUTHKEY`, `TS_AUTH_KEY`, or `TS_CLIENT_SECRET` SHALL be rejected for federated HTTP startup before acquisition or enrollment because they can conflict with or bypass the selected credential. The system SHALL NOT alter those environment variables globally to conceal conflicts.

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

#### Scenario: Provider startup is canceled
- **WHEN** startup is canceled during provider acquisition before SDK initialization
- **THEN** acquisition observes cancellation and neither `tsnet.Start()` nor listener binding begins

#### Scenario: Configured audience accompanies a supplied token
- **WHEN** a legacy inline/file or provider-backed federated credential contains an audience
- **THEN** tsnet receives a single supplied assertion and client ID without a simultaneous audience selector

#### Scenario: Ambient tsnet credential would override federation
- **WHEN** a conflicting tsnet credential environment variable is nonempty during federated HTTP startup
- **THEN** startup rejects the conflict with the variable name but without its value and does not silently use another identity

### Requirement: Federated assertions can be refreshed through a file
The system SHALL continue accepting federated credential JSON containing `clientId` and exactly one of inline `idToken`, legacy `idTokenFile`, or supported explicit `provider`. Provider-specific configuration SHALL follow the workload-identity-provider requirements. For legacy file-backed credentials, the Admin API federation callback SHALL reread and trim the file on each assertion acquisition. Missing, unreadable, or empty files SHALL return errors without falling back to a previous assertion. Both typed and generic Admin API clients SHALL use this behavior, and token contents SHALL NOT be logged.

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
- **WHEN** federated JSON supplies more than one of `idToken`, `idTokenFile`, or `provider`, or supplies none
- **THEN** parsing fails with an actionable validation error

#### Scenario: Existing inline credentials are used
- **WHEN** an existing valid inline federated credential is configured
- **THEN** it continues to authenticate without requiring a token file or provider

### Requirement: Federation refresh scope is explicit
The system SHALL initialize tsnet from the current assertion snapshot and SHALL document the distinction between Admin API refresh, provider token issuance, and node enrollment. Legacy file refresh SHALL remain externally managed; Kubernetes projected-token issuance and rotation SHALL be kubelet-managed; AWS/GCP provider tokens SHALL be acquired by the application as needed for authentication. None of these SHALL be described as guaranteed continuous tsnet reauthentication refresh. Documentation SHALL require external refreshers to protect files and replace them atomically, and projected-token deployments to preserve kubelet rotation semantics.

#### Scenario: Operator configures long-running federation
- **WHEN** an operator follows credential documentation
- **THEN** it distinguishes Admin API access-token refresh from tsnet's startup snapshot and explains each source's issuance, rotation, protection, and re-enrollment limitations

#### Scenario: Operator deploys a cloud provider credential
- **WHEN** an operator selects AWS or GCP provider mode
- **THEN** documentation explains that the application acquires current platform assertions but does not continuously replace tsnet's enrollment assertion after startup
