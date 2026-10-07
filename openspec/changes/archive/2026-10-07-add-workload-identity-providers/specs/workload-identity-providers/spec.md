## ADDED Requirements

### Requirement: Federated provider selection is explicit and unambiguous
The system SHALL accept `provider` values `kubernetes`, `aws`, and `gcp` in the existing federated JSON credential. Provider mode SHALL require a nonblank `clientId` and `audience`, and SHALL be mutually exclusive with `idToken` and `idTokenFile`. `tokenFile` SHALL be valid only for Kubernetes, with an absent value defaulting to `/var/run/secrets/tailscale/token`; `region` SHALL be valid only for AWS. Explicitly blank provider-specific settings, invalid field types, unsupported providers, and provider settings on OAuth or bearer credentials SHALL fail configuration validation before provider I/O. Provider selection SHALL NOT be inferred from ambient cloud environment variables. A valid provider credential without explicit `type` SHALL classify as federated; audience alone SHALL NOT select a provider.

#### Scenario: Operator configures an explicit cloud source
- **WHEN** credential JSON has a supported provider, client ID, audience, and valid provider-specific settings
- **THEN** the credential selects only that provider without requiring an inline assertion or external assertion file

#### Scenario: Operator supplies competing sources
- **WHEN** provider mode is combined with `idToken` or `idTokenFile`
- **THEN** configuration fails before file, metadata, or STS access

#### Scenario: Unsupported or inappropriate settings are supplied
- **WHEN** the provider is `azure`, `auto`, unknown, or has settings belonging to a different provider or credential type
- **THEN** configuration fails with sanitized guidance rather than ignoring the settings or selecting another source

#### Scenario: Provider detection is not configured
- **WHEN** only `clientId` and `audience` are provided, even in an identifiable cloud environment
- **THEN** configuration fails without automatically probing providers

### Requirement: Kubernetes assertions use rotating projected service-account tokens
The Kubernetes provider SHALL reopen the configured projected-token path on every assertion acquisition, follow the current projection symlink target, trim whitespace, and accept only a regular file containing at most 1 MiB. It SHALL NOT write the file, call the Kubernetes TokenRequest API, or implicitly use the default Kubernetes API service-account token path. Missing, unreadable, empty, oversized, or invalid token files SHALL fail without stale-assertion fallback. Documentation SHALL require kubelet-managed audience-specific projection, a read-only volume mount without `subPath`, restricted token access, and publicly reachable issuer discovery/JWKS trusted by Tailscale.

#### Scenario: Kubelet rotates the projected token
- **WHEN** the projection symlink changes and a client next needs an assertion
- **THEN** the new target's token is acquired without restarting the MCP server or retaining the old open file

#### Scenario: Dedicated token volume is absent
- **WHEN** the configured or dedicated default path does not exist
- **THEN** acquisition fails and does not try the Kubernetes API token, a cloud metadata source, or a prior token

#### Scenario: Invalid file source is configured
- **WHEN** the token path resolves to a non-regular file, contains more than 1 MiB, or becomes unreadable
- **THEN** acquisition returns a sanitized failure without token disclosure or a truncated assertion

### Requirement: AWS assertions use regional STS web identity issuance
The AWS provider SHALL load AWS SDK v2 configuration lazily, use its refreshable credential chain, and invoke regional STS `GetWebIdentityToken` with the configured audience as a single-element audience list, signing algorithm `ES384`, and duration 300 seconds. Region resolution SHALL prefer explicit `region`, then SDK environment/shared configuration, then bounded EC2 IMDS discovery. It SHALL NOT substitute GetCallerIdentity signatures or directly treat an AWS access key as an OIDC assertion. Documentation SHALL explain workload-role setup, SDK credential precedence, EKS credential-chain prerequisites, explicit region configuration where IMDS is unavailable, and `sts:GetWebIdentityToken` permission with audience/duration restrictions.

#### Scenario: Workload role issues a token
- **WHEN** the SDK obtains workload credentials and a region for an authorized AWS role
- **THEN** acquisition calls STS with the documented parameters and returns its validated identity JWT

#### Scenario: Configured region overrides environment
- **WHEN** JSON specifies a region different from SDK environment configuration
- **THEN** the explicit region determines the STS endpoint and no region metadata discovery is attempted

#### Scenario: AWS identity issuance fails
- **WHEN** credentials, region discovery, or `GetWebIdentityToken` fails or returns an empty token
- **THEN** acquisition fails with sanitized AWS setup guidance without switching providers or exposing raw SDK errors

### Requirement: GCP assertions use the attached identity metadata endpoint
The GCP provider SHALL request the default attached service account's identity token from `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity`, using URL-encoded `audience`, `format=full`, and `Metadata-Flavor: Google`. It SHALL require HTTP 200, a `Metadata-Flavor: Google` response header, and a bounded valid JWT body. The production endpoint SHALL be fixed and SHALL NOT be overridden by tool arguments or `GCE_METADATA_HOST`. It SHALL NOT fall back to user ADC, key files, impersonation, or another provider. Documentation SHALL scope support to environments exposing this identity endpoint with suitable service-account permissions and Tailscale trust.

#### Scenario: Attached service account obtains a token
- **WHEN** a configured GCP workload acquires an assertion
- **THEN** the request uses the fixed identity endpoint, configured audience, full token format, and metadata header

#### Scenario: Metadata server returns a non-identity response
- **WHEN** metadata responds with a non-200 status, missing required header, empty body, malformed JWT, or oversized body
- **THEN** acquisition fails without accepting the response as an assertion or trying a different identity source

### Requirement: Provider acquisition is bounded and cancellation-aware
Provider acquisition SHALL observe the initiating context and use an overall maximum 30-second budget without extending a shorter caller deadline. Cloud HTTP requests SHALL use a maximum five-second per-request timeout, normal TLS verification where HTTPS applies, disabled redirects and environment proxies, and finite retries bounded by the acquisition context. Provider token and response bodies SHALL be limited to 1 MiB, rejecting overflow. Kubernetes file acquisition SHALL check context before and after reading and require a local regular projected file; documentation SHALL not promise cancellation of arbitrary blocked filesystem I/O. Tests SHALL inject provider dependencies without changing global transports or requiring live cloud access.

#### Scenario: Caller cancels acquisition
- **WHEN** the calling request is canceled during metadata, AWS credential, or STS I/O
- **THEN** the acquisition stops through its context and no protected Admin API request is sent

#### Scenario: Caller has a shorter deadline
- **WHEN** assertion acquisition starts with less than 30 seconds remaining
- **THEN** acquisition honors that shorter deadline rather than starting a fresh unrestricted budget

#### Scenario: Token endpoint redirects
- **WHEN** an acquisition response redirects to a different URL
- **THEN** the acquisition fails without forwarding a credential-bearing request to that target

### Requirement: Provider assertions are validated without authorizing callers
Before exchanging a provider assertion or supplying it to tsnet, the system SHALL trim it and require a well-formed compact JWT, decodable claims, a numeric future expiration, and an audience matching the configured value as a string or element of a string array. These local checks SHALL NOT be represented as signature or issuer verification; Tailscale SHALL remain the authority for signature, issuer, subject, and trust-claim checks. The system SHALL NOT derive MCP grants from decoded claims or persist/cache provider assertions for reuse after a refresh failure.

#### Scenario: Projected token has the Kubernetes API audience
- **WHEN** the token audience does not contain the configured Tailscale audience
- **THEN** acquisition fails before a Tailscale exchange or node enrollment attempt

#### Scenario: Token is expired or malformed
- **WHEN** provider output lacks a valid future expiration or valid JWT claims
- **THEN** it is rejected without logging the token or its payload

#### Scenario: Token matches local sanity checks but not trust policy
- **WHEN** Tailscale rejects a locally well-formed token's signature, issuer, subject, or claims
- **THEN** authentication fails and no MCP caller permissions are granted by its decoded contents

### Requirement: Provider failures and informational commands are secret-safe
Acquisition and exchange failures SHALL use sanitized provider/stage guidance, preserve context cancellation/deadline identity, and omit assertions, AWS credentials, provider response bodies, and raw SDK errors from logs and client errors. `--version` and `--list-groups` SHALL not read token files, initialize provider SDK configuration, acquire tokens, or contact cloud/identity endpoints, regardless of credential or provider environment variables. Provider authentication SHALL not expose a token-fetching MCP tool, resource, or prompt, change grant names, or retry a protected API mutation after an authentication failure.

#### Scenario: Provider error includes secret material
- **WHEN** a provider or Tailscale exchange returns an error containing credentials or a JWT
- **THEN** logs and returned failures contain only sanitized guidance and no secret material

#### Scenario: Offline command has unusable provider configuration
- **WHEN** an informational command runs with missing files, invalid provider configuration, or unreachable cloud metadata
- **THEN** it succeeds using its existing offline behavior without inspecting those identity sources

#### Scenario: Provider refresh fails before a mutation
- **WHEN** a permitted mutating tool needs an access token and acquisition fails
- **THEN** the protected mutation is not sent or automatically retried and its MCP grants and confirmation rules remain unchanged
