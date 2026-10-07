## Purpose

Define the Aperture MCP tool surface, offline API contract, identity-aware client, and safe configuration and pricing operations.

## Requirements

### Requirement: Aperture requires explicit HTTP opt-in
The system SHALL support boolean `--aperture` / `TS_MCP_APERTURE`, defaulting to false, independently of boolean `--tailscale` / `TS_MCP_TAILSCALE`, defaulting to true. Explicit flags SHALL override environment values, including `--tailscale=false` overriding `TS_MCP_TAILSCALE=true`. `--aperture` and `--aperture=true` SHALL enable Aperture in HTTP mode; an explicit `--aperture=false` SHALL override `TS_MCP_APERTURE=true`. Configuring `--aperture-url` / `APERTURE_URL` alone SHALL NOT enable Aperture. When disabled, the system SHALL NOT validate the Aperture URL, construct its upstream client, register its tools, or log its endpoint URLs, and `/aperture/mcp` SHALL return 404 on tailnet and enabled loopback listeners. Aperture enablement SHALL NOT change Tailscale enablement. Stdio SHALL ignore Aperture enablement and URL configuration, remain Tailscale-only, and require Tailscale enabled for serving.

#### Scenario: Aperture runs without the Tailscale MCP service
- **WHEN** HTTP serving starts with `--tailscale=false --aperture`
- **THEN** Aperture uses the shared tsnet transport and node identity with the existing enrollment credential and advertised tags where applicable, without requiring `TAILSCALE_TAILNET` or Admin API read scopes
- **AND** `/mcp` and `/tailscale/mcp` return 404 on both enabled listener types, no Tailscale tools, resources, prompts, or Admin API clients are initialized, no Admin API validation occurs, and no Tailscale MCP endpoint URLs are logged

#### Scenario: Aperture is disabled by default
- **WHEN** HTTP serving starts with Tailscale enabled and without an Aperture enablement flag or environment opt-in
- **THEN** only the Tailscale service is available, no Aperture tools or client are initialized, no Aperture endpoint URLs are logged, and `/aperture/mcp` returns 404 on both enabled listener types

#### Scenario: URL configuration does not enable Aperture
- **WHEN** only `--aperture-url` or `APERTURE_URL` is configured, even with a malformed URL
- **THEN** Aperture remains disabled and the URL is not validated or used to construct an upstream client

#### Scenario: Operator enables Aperture
- **WHEN** HTTP serving starts with `--aperture=true`, bare `--aperture`, or `TS_MCP_APERTURE=true` without a flag override
- **THEN** its route, five tools, upstream client, and endpoint URL logs are enabled independently of whether Tailscale MCP is enabled

#### Scenario: Explicit false overrides environment opt-in
- **WHEN** HTTP serving starts with `TS_MCP_APERTURE=true` and `--aperture=false`, even with a malformed Aperture URL
- **THEN** Aperture remains disabled without URL validation, client construction, tool registration, or endpoint URL logs, and its route returns 404 on both enabled listener types

#### Scenario: Stdio ignores Aperture settings
- **WHEN** stdio starts with Tailscale enabled, Aperture enabled by flag or environment, and a malformed Aperture URL
- **THEN** it serves only Tailscale without validating the URL, initializing an Aperture client, registering Aperture tools, or opening HTTP listeners

### Requirement: Aperture contract is cached for offline use
The repository SHALL retain the Aperture OpenAPI document at `tools/aperture/openapi.json` and metadata identifying its source URL, retrieval date, SHA-256, API/OpenAPI versions, and operation/path counts. The initial source SHALL be `http://ai/aperture/openapi.json`. Builds, automated tests, startup, and tool registration SHALL NOT fetch the live schema. An explicit refresh command SHALL validate a downloaded candidate before replacing the snapshot and metadata, preserving the previous cache on download or validation failure.

#### Scenario: Development runs outside the tailnet
- **WHEN** builds, automated tests, or offline metadata inspection run without access to `ai`
- **THEN** they use the checked-in contract and do not attempt a schema download

#### Scenario: Operator refreshes the contract
- **WHEN** an operator explicitly refreshes from a reachable schema source
- **THEN** a valid candidate and matching metadata replace the cache and operation coverage drift is detectable by tests

#### Scenario: Refresh fails
- **WHEN** the source is unreachable or returns an invalid schema
- **THEN** refresh fails and the existing snapshot and metadata remain intact

### Requirement: All cached Aperture operations have explicit tool mappings
When enabled in HTTP mode, the Aperture MCP server SHALL expose exactly the following initial mappings as typed tools with matching trusted metadata. Every cached operation SHALL have one documented mapping; coverage tests SHALL detect missing, duplicate, or stale mappings. No Aperture resources or prompts SHALL be introduced.

| Method and path | Operation ID | Tool and exact grant | Group | Read-only |
| --- | --- | --- | --- | --- |
| `GET /config` | `get-config` | `aperture_get_config` | `aperture-config` | yes |
| `POST /config:validate` | `validate-config` | `aperture_validate_config` | `aperture-config` | yes |
| `PUT /config` | `set-config` | `aperture_set_config` | `aperture-config` | no |
| `GET /pricing` | `get-pricing` | `aperture_get_pricing` | `aperture-pricing` | yes |
| `GET /pricing/{model}` | `get-model-pricing` | `aperture_get_model_pricing` | `aperture-pricing` | yes |

#### Scenario: Contract coverage is checked
- **WHEN** the cached schema is compared with production registrations and trusted metadata
- **THEN** each of its five operations maps exactly once with the documented method, path, name, group, and read-only classification

#### Scenario: Upstream adds an operation
- **WHEN** an explicit schema refresh introduces an unmapped operation
- **THEN** the coverage check fails without automatically registering or granting the new operation

### Requirement: Aperture requests use a bounded identity-aware client
When Aperture is enabled for HTTP serving, the system SHALL use `--aperture-url` / `APERTURE_URL`, defaulting to `http://ai/aperture`, as its fixed operator-configured API base. Only in that mode SHALL invalid HTTP(S) URLs or URLs containing userinfo, query, or fragment be rejected before serving. The client SHALL preserve the base path, dial through the running MCP tsnet node, verify HTTPS certificates normally, disable environment proxies and redirects, propagate cancellation, impose a 30-second request timeout, and limit response bodies to 16 MiB. It SHALL NOT forward Admin API credentials, incoming cookies, or caller identity headers. Upstream availability SHALL NOT be a startup prerequisite. Disabled Aperture and stdio SHALL NOT validate the URL or initialize this client.

#### Scenario: Enabled Aperture has an invalid base URL
- **WHEN** HTTP serving starts with `--aperture` and an invalid base URL or one containing userinfo, query, or fragment
- **THEN** startup fails before serving

#### Scenario: Deployment uses tsnet without host Tailscale
- **WHEN** an authorized caller invokes an Aperture operation
- **THEN** the request uses the MCP tsnet node's identity and configured base path without relying on the host network identity

#### Scenario: Aperture is unavailable
- **WHEN** Aperture is enabled in HTTP mode and cannot be reached but startup otherwise succeeds
- **THEN** all enabled MCP routes remain served and Aperture calls return bounded tool errors without preventing Tailscale operations when Tailscale is enabled

#### Scenario: Redirect or oversized response is received
- **WHEN** the backend redirects or exceeds the response limit
- **THEN** the client does not follow the redirect or return truncated successful data and instead reports a sanitized tool error

#### Scenario: Caller cancels an operation
- **WHEN** the MCP request context is canceled
- **THEN** the upstream request is canceled rather than continuing detached work

### Requirement: Configuration reads and validation preserve non-mutating semantics
`aperture_get_config` SHALL return the backend-redacted HuJSON `config` string and upstream `etag`. `aperture_validate_config` SHALL require a nonblank string `config`, send it only to `POST /config:validate`, and return structured `valid` and sanitized `errors` fields without saving configuration. Tool descriptions SHALL state that configuration reads require upstream admin and that validation inputs may contain secrets. Invalid input SHALL fail before upstream access.

#### Scenario: Caller reads configuration
- **WHEN** an authorized read succeeds with an ETag
- **THEN** the tool returns the redacted config and exact ETag for a later conditional replacement

#### Scenario: Caller validates configuration
- **WHEN** an authorized caller supplies a config string
- **THEN** only the validation endpoint is called, the validation result is returned, and no configuration write occurs

#### Scenario: Config input is absent or invalid
- **WHEN** validation receives missing, non-string, or blank config
- **THEN** it returns an input error without contacting Aperture

### Requirement: Configuration replacement requires confirmation and concurrency protection
`aperture_set_config` SHALL require a full nonblank HuJSON `config` string, a single concrete `if_match` ETag, and `confirm` equal to `aperture_set_config`. It SHALL reject missing or invalid inputs, wildcard validators, and ETag lists before backend access. It SHALL send the ETag unchanged in `If-Match` and only the config in the PUT body. The tool SHALL be annotated mutating and destructive, describe redacted-key round-trip risks, and return only the backend-redacted saved config and new ETag on success. It SHALL NOT silently merge, substitute a fresh ETag, retry a write automatically, or claim rollback on failure.

#### Scenario: Caller confirms a current replacement
- **WHEN** an authorized caller provides the full replacement, current ETag, and exact confirmation
- **THEN** one conditional PUT is made and success returns the saved redacted config and new ETag

#### Scenario: Confirmation or concurrency guard is invalid
- **WHEN** confirmation is wrong or absent, or `if_match` is absent, blank, malformed, a wildcard, or an ETag list
- **THEN** the tool fails before any PUT request

#### Scenario: Configuration changed concurrently
- **WHEN** the backend returns 412
- **THEN** the tool reports a conflict and requires a new read and deliberate retry without performing another write

#### Scenario: Write response is lost
- **WHEN** a write times out or loses its response
- **THEN** the tool reports an uncertain outcome and directs the caller to inspect state without retrying or claiming success

### Requirement: Pricing tools preserve conditional and exact-model semantics
Pricing tools SHALL support optional `if_none_match` mapped to `If-None-Match`. Full pricing SHALL call `GET /pricing`; model pricing SHALL require a nonblank exact `model` and call `GET /pricing/{model}` using safe path construction that supports slash-separated identifiers without path traversal or query injection. The client SHALL normalize HuJSON when necessary and preserve decimal price strings, units, cost bases, models, and configured adjustments as structured JSON. A 200 response SHALL return `data`, `etag`, and `not_modified: false`; 304 SHALL return `etag` and `not_modified: true` without requiring a body, using the submitted validator if the response omits ETag. No pagination or model-access filtering SHALL be invented.

#### Scenario: Pricing has comments or trailing commas
- **WHEN** a successful pricing response is formatted as HuJSON
- **THEN** it is returned as structured JSON without changing decimal strings or measurement units

#### Scenario: Model name contains a slash
- **WHEN** a caller requests an exact model such as `provider/model`
- **THEN** the API receives that model identifier under the configured pricing path without losing the base prefix or injecting a query

#### Scenario: Model name attempts traversal
- **WHEN** a model contains empty or dot traversal path segments
- **THEN** the tool rejects it before backend access

#### Scenario: Pricing is unchanged
- **WHEN** a conditional pricing request receives 304 with no body
- **THEN** the tool returns a successful not-modified result rather than a JSON decoding failure

#### Scenario: Model has no useful pricing
- **WHEN** model pricing returns an empty `models` object
- **THEN** the tool preserves that successful empty result

### Requirement: Aperture failures are structured and secret-safe
Aperture tools SHALL mark authorization, input, upstream HTTP, network, and decoding failures as protocol or tool errors, never successful error text. They SHALL preserve safe HTTP status classification for RFC 9457 errors, including 403, 412, 422, and 5xx, without reflecting raw upstream bodies, submitted config, credentials, or untrusted error values/messages. Validation diagnostics SHALL be sanitized, falling back to generic guidance when safe disclosure cannot be established. Malformed or oversized responses SHALL NOT become partial successes. Documentation SHALL distinguish MCP grants from upstream admin and `read_pricing: true`; admin alone SHALL NOT be represented as sufficient for pricing.

#### Scenario: Backend rejects pricing permission
- **WHEN** the backend returns 403 for pricing
- **THEN** the caller receives a sanitized tool error explaining the separate upstream pricing permission without expanding MCP grants

#### Scenario: Validation error echoes a secret
- **WHEN** an upstream validation result or Problem Details body contains submitted provider credentials
- **THEN** returned diagnostics and logs do not expose those credentials or the submitted configuration

#### Scenario: Backend returns malformed data
- **WHEN** an otherwise successful HTTP response cannot be decoded according to the operation contract
- **THEN** the tool returns a sanitized error rather than empty or partial success
