## Purpose

Define how remaining Tailscale OpenAPI endpoints are exposed through generic MCP tools and resources.

## Requirements

### Requirement: OpenAPI gaps are exposed as MCP tools
The system SHALL expose each Tailscale OpenAPI gap as an MCP tool with typed inputs, structured JSON output, grant enforcement, and confirmation for mutating operations.

#### Scenario: Read endpoint tool is registered
- **WHEN** the MCP server starts
- **THEN** every in-scope operation has a corresponding tool named with lower snake case action-object naming

#### Scenario: Endpoint tool is called
- **WHEN** an authorized user calls an endpoint tool with valid inputs
- **THEN** the tool calls the matching Tailscale API operation and returns structured JSON output

#### Scenario: Endpoint tool is denied
- **WHEN** a user without the required tool grant calls an endpoint tool
- **THEN** the tool returns a permission error without calling the Tailscale API

### Requirement: Stable read state is exposed as MCP resources
The system SHALL expose stable read-only collections and entities as MCP resources when a natural `tailscale://` URI exists.

#### Scenario: Stable collection resource is registered
- **WHEN** a stable collection endpoint is implemented
- **THEN** the MCP server exposes a resource URI for that collection with JSON content and resource grant enforcement

#### Scenario: Parameterized entity resource is read
- **WHEN** an authorized user reads an entity resource with required path arguments
- **THEN** the MCP server calls the matching Tailscale API operation and returns JSON content for that entity

### Requirement: Mutating operations require explicit confirmation
The system SHALL require mutating operations to include a confirmation token matching the OpenAPI operation ID before calling the Tailscale API.

#### Scenario: Mutating tool is confirmed
- **WHEN** an authorized user calls a mutating tool with `confirm` equal to the operation ID
- **THEN** the tool calls the matching Tailscale API operation

#### Scenario: Mutating tool is not confirmed
- **WHEN** an authorized user calls a mutating tool without the required confirmation token
- **THEN** the tool returns an error without calling the Tailscale API

### Requirement: API errors are returned as structured tool results
The system SHALL return Tailscale API failures as structured JSON errors that include operation context, HTTP status, and response message when available.

#### Scenario: Tailscale API returns an error
- **WHEN** the upstream Tailscale API returns a non-success response
- **THEN** the MCP tool returns an error result containing operation ID, status code, and sanitized response body

### Requirement: Coverage mappings reflect implemented endpoints
The system SHALL update MCP coverage metadata for each newly implemented endpoint.

#### Scenario: Coverage is regenerated
- **WHEN** `make coverage` runs after endpoint implementation
- **THEN** implemented endpoints are marked `implemented` with MCP names, resource URIs where applicable, grant permissions, confirmation metadata where applicable, and rationale

#### Scenario: Full coverage is implemented
- **WHEN** `make coverage` runs after this change
- **THEN** every OpenAPI operation is marked implemented with no gaps

### Requirement: Network flow logs are retrieved in bounded chronological chunks
The system SHALL expose `tailscale_list_network_flow_logs` as a read-only MCP tool that retrieves Tailscale `GET /tailnet/{tailnet}/logging/network` data in chronological windows no longer than five minutes. An initial call MUST provide RFC3339 `start` and `end` timestamps with `start` before `end`; it MUST retrieve only the first bounded window of that range.

#### Scenario: Initial request returns the first chunk
- **WHEN** an authorized caller provides a valid network-flow-log `start` and `end` interval longer than five minutes
- **THEN** the tool calls the Tailscale endpoint only for the first five minutes and returns that window's logs

#### Scenario: Short interval is retrieved once
- **WHEN** an authorized caller provides a valid interval no longer than five minutes
- **THEN** the tool calls the Tailscale endpoint for the complete interval and does not require a continuation

#### Scenario: Invalid initial range is rejected
- **WHEN** a caller omits either range timestamp, provides an invalid timestamp, or provides an end that is not after start
- **THEN** the tool returns an input error without calling the Tailscale API

### Requirement: Network flow log chunks support opaque continuation
The system SHALL return each successful network-flow-log result as structured JSON containing `logs`, the effective chunk `start` and `end`, and `nextCursor` when unqueried time remains. The cursor SHALL encode continuation state opaquely; a continuation call MUST accept the cursor without requiring new range timestamps and retrieve the next chronological window from the original interval.

#### Scenario: A response has more chunks
- **WHEN** an initial or continuation request leaves time remaining in its requested interval
- **THEN** the response includes a non-empty `nextCursor` for the next chronological chunk

#### Scenario: A response completes the requested interval
- **WHEN** the returned chunk reaches the requested end timestamp
- **THEN** the response omits `nextCursor` or returns it as null

#### Scenario: A caller continues with a cursor
- **WHEN** an authorized caller supplies a valid `nextCursor`
- **THEN** the tool queries the next bounded window and returns its logs and any further continuation cursor

#### Scenario: A cursor is invalid or conflicts with a range
- **WHEN** a caller supplies a malformed cursor or combines a cursor with start or end timestamps
- **THEN** the tool returns an input error without calling the Tailscale API

### Requirement: Network flow log chunking preserves read authorization
The system SHALL require the existing `tool:tailscale_list_network_flow_logs` grant before validating a continuation or calling the network-flow-log endpoint. The chunking interface SHALL remain read-only and SHALL not introduce a new tool grant, resource, prompt, or mutating operation.

#### Scenario: Unauthorized caller requests a chunk
- **WHEN** a caller without the network-flow-log tool grant invokes the tool with an initial range or cursor
- **THEN** the tool returns a permission error without calling the Tailscale API

#### Scenario: Upstream chunk retrieval fails
- **WHEN** Tailscale returns a non-success response for a bounded network-flow-log request
- **THEN** the tool returns the existing sanitized API error and does not return a continuation cursor

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
