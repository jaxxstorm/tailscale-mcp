## ADDED Requirements

### Requirement: Organization tailnets are listed with explicit pagination
The system SHALL expose `tailscale_list_organization_tailnets` for `listOrganizationTailnets` as a read-only tool requiring a nonblank string `organization`, accepting optional integer `limit` from 1 through 100 and optional string `cursor`. It SHALL call `GET /organizations/{organization}/tailnets` once per invocation and return the upstream JSON including `tailnets`, `cursor`, and `totalCount` without automatically retrieving later pages.

#### Scenario: Authorized caller lists a page
- **WHEN** an authorized caller provides an organization, valid limit, and opaque cursor
- **THEN** the tool escapes the organization as one path segment, forwards the query values, and returns the page and pagination metadata unchanged

#### Scenario: Caller uses upstream defaults
- **WHEN** an authorized caller supplies organization `-` without limit or cursor
- **THEN** the tool uses the documented current-organization shorthand and omits pagination arguments so the upstream limit defaults to 100

#### Scenario: Pagination or organization is invalid
- **WHEN** organization is missing, blank, or non-string, or limit is a string, fractional, below 1, or above 100, or cursor is non-string
- **THEN** the tool returns an input error without making an upstream request

#### Scenario: A page fails
- **WHEN** the upstream list request fails
- **THEN** the tool returns a sanitized error with operation context and available HTTP status/message rather than a successful partial page or invented cursor

### Requirement: API-only tailnet creation preserves one-time credentials
The system SHALL expose `tailscale_create_organization_tailnet` for `createOrganizationTailnet`, requiring a nonblank string `organization`, a required object `body` containing nonblank string `displayName`, and `confirm` equal to `createOrganizationTailnet`. The tool SHALL POST to `/organizations/{organization}/tailnets` and preserve successful response fields, including `oauthClient.secret` and `alreadyExists`. Tool documentation SHALL identify Alpha status, API-only semantics, and sensitive one-time credential output. The system SHALL NOT log the returned OAuth secret or automatically retry creation.

#### Scenario: Authorized creation succeeds
- **WHEN** an authorized caller supplies a valid organization, body, and confirmation and upstream returns 200
- **THEN** the tool returns the complete JSON response including the OAuth client and `alreadyExists` without treating that flag as a reason to discard credentials

#### Scenario: Creation inputs or confirmation are invalid
- **WHEN** body or displayName is missing or wrongly typed, displayName or organization is blank, or confirmation is missing or incorrect
- **THEN** the tool returns an input or confirmation error without making an upstream request

#### Scenario: Creation fails after dispatch
- **WHEN** the upstream creation request fails or its outcome cannot be determined
- **THEN** the tool returns a sanitized failure, does not claim successful creation, does not retry, and does not expose credentials in logs or error payloads

### Requirement: Tailnet deletion requires an explicit configured target
The system SHALL expose `tailscale_delete_tailnet` for `deleteTailnet` with required string `tailnet` and `confirm` equal to `deleteTailnet`. The supplied target MUST exactly equal the explicitly configured tailnet; blank targets, `-`, implicit defaults, and mismatches MUST be rejected. The tool SHALL use the existing configured credential and issue a bodyless DELETE only after authorization, target validation, and confirmation succeed. It SHALL NOT exchange credentials or infer the target from previous operations. Its description SHALL warn that deletion removes all users, devices, and configuration.

#### Scenario: Confirmed configured tailnet is deleted
- **WHEN** an authorized caller supplies an exact explicit configured target and correct confirmation
- **THEN** the tool sends DELETE to that target with the configured credential and treats an empty upstream 200 response as success

#### Scenario: Target is unsafe
- **WHEN** either configured or supplied target is blank or `-`, the supplied target is absent or non-string, or the targets differ
- **THEN** no upstream request occurs even if operation confirmation is correct

#### Scenario: Deletion is not confirmed
- **WHEN** the target matches but confirmation is absent or differs from `deleteTailnet`
- **THEN** no upstream request occurs

#### Scenario: Configured credential cannot delete the target
- **WHEN** upstream rejects the deletion credential
- **THEN** the tool returns a sanitized error with operation and HTTP status context without exchanging tokens or retrying with another credential

### Requirement: Refreshed schema extensions remain compatible
The system SHALL preserve service `displayName` through existing list/get/update tools and service resources, accept and return log-streaming destination `crowdstrike`, and preserve refreshed configuration-audit event, origin, and actor values through existing JSON interfaces. Existing grants and confirmations SHALL remain unchanged. Newly documented 400/402 failures SHALL remain failures with available sanitized status/message information rather than success results.

#### Scenario: Service and logging payloads contain new fields
- **WHEN** an authorized caller writes or reads a service displayName or CrowdStrike log-streaming configuration
- **THEN** existing tools forward or return the field unchanged, and service resource output retains displayName

#### Scenario: Audit data contains refreshed values
- **WHEN** an authorized caller filters by a new audit event such as `GROUP.UPDATE.USER_ROLE` or a refreshed PAM event, or upstream returns `BORDER0_API`, `PAM_CONNECTOR`, or `PAM_SERVICE_ACCOUNT`
- **THEN** the existing string-filter interface forwards the event and JSON output preserves the returned values without requiring new grants

#### Scenario: Authorization or approval fails with a billing restriction
- **WHEN** authorizeDevice or approveUser returns 402, or authorizeDevice returns the documented 400
- **THEN** the existing tool returns a sanitized failure retaining available status/message information without leaking unrelated response fields or credentials
