## Purpose

Define fail-closed MCP grant evaluation, caller-filtered discovery, and trusted tool metadata.

## Requirements

Tailscale-specific registration, discovery, and execution requirements below apply when Tailscale MCP is enabled. Disabling Tailscale SHALL omit its tools, resources, prompts, and catalog entries; exact, wildcard, and group grants SHALL NOT enable a disabled service.

### Requirement: Matching MCP capability entries are unioned
The system SHALL parse all matching `jaxxstorm.com/cap/mcp` capability entries once per tailnet request and union their tool and resource permissions into typed request context. Missing capabilities SHALL authorize no operations; malformed capability data SHALL fail closed. Client-supplied identity or grant headers SHALL NOT establish permissions.

#### Scenario: Multiple rules grant distinct operations
- **WHEN** two matching capability entries grant different tools or resources
- **THEN** the caller can use the union of those permissions without obtaining permissions absent from both entries

#### Scenario: Malformed capability accompanies a valid entry
- **WHEN** one matching capability entry is malformed
- **THEN** the request is rejected before any tool or resource accesses Tailscale data

#### Scenario: Capabilities are missing or spoofed
- **WHEN** a request has no trusted capability context, even if it supplies identity or grant headers
- **THEN** no protected operation is authorized

### Requirement: Resource permissions use explicit boundaries
The system SHALL authorize a resource only by exact URI, global `*`, or an explicit trailing `/*` selector matching a non-empty descendant under that slash. Empty selectors and implicit prefixes SHALL NOT authorize resources. Tool selectors SHALL NOT grant resource access.

#### Scenario: Exact resource name does not grant a similar name
- **WHEN** the resource grant is `tailscale://device`
- **THEN** it does not authorize `tailscale://devices` or descendants of either URI

#### Scenario: Explicit descendant grant is bounded
- **WHEN** the resource grant is `tailscale://devices/*`
- **THEN** it authorizes `tailscale://devices/123` but not `tailscale://devices`, `tailscale://devices/`, or `tailscale://devices-other/123`

#### Scenario: Empty resource grant is denied
- **WHEN** a capability contains an empty resource selector and no other matching selector
- **THEN** a resource read is denied before an Admin API call

#### Scenario: Tool permission does not imply resource permission
- **WHEN** a caller has `tools: ["read:*"]` but no resource permissions
- **THEN** resource reads remain denied

### Requirement: Tool selectors use trusted registration metadata
The system SHALL support exact tool names, `*`, `read:*`, `group:<name>`, and `group:<name>:read` in tool grants with OR semantics. Read-only and group matching SHALL use server-maintained metadata for registered tools, never client annotations or tool-name heuristics. Unknown or unsupported selectors SHALL match nothing. Mutation confirmations SHALL remain required for all authorized mutating tools.

#### Scenario: Read selector excludes mutations
- **WHEN** a caller is granted only `read:*`
- **THEN** registered read-only tools are authorized and mutating tools are denied, including mutating operations whose names begin with get

#### Scenario: Group selector includes writes
- **WHEN** a caller is granted `group:dns`
- **THEN** registered DNS readers and writers are authorized, and writers still require their existing confirmation tokens

#### Scenario: Read-only group selector is narrow
- **WHEN** a caller is granted `group:dns:read`
- **THEN** only read-only tools in the DNS group are authorized

#### Scenario: Selectors form a union
- **WHEN** a caller is granted both `read:*` and `group:dns`
- **THEN** all registered readers plus DNS writers are authorized rather than only DNS readers

#### Scenario: Invalid selector does not expand access
- **WHEN** the only grant is an unknown group or unsupported selector syntax
- **THEN** no tool is authorized by that selector

#### Scenario: Existing exact grants remain valid
- **WHEN** a caller uses an existing generated or curated tool's exact grant name
- **THEN** it retains authorization to that tool with its unchanged schema and confirmation requirements

### Requirement: Tool discovery and execution share authorization
The system SHALL filter `tools/list` by the current request's grants and SHALL reject unauthorized `tools/call` before handler side effects on each enabled service, including both `/mcp` and `/tailscale/mcp` Tailscale aliases. The Tailscale aliases SHALL use identical grant enforcement on tailnet and explicitly enabled loopback, using identity-derived grants for tailnet and only operator-configured grants for loopback. Handler-level permission checks SHALL remain authoritative in addition to SDK filtering, using the same evaluator and the target service's metadata. Permission denials SHALL be protocol errors or tool error results, never successful text results.

#### Scenario: Caller lists permitted tools
- **WHEN** a caller requests `tools/list` on either service route
- **THEN** every returned tool is registered on that route and authorized for that caller and ungranted tools are omitted

#### Scenario: Caller invokes an unlisted tool directly
- **WHEN** a caller submits `tools/call` for an ungranted tool with otherwise valid inputs and confirmation
- **THEN** the call fails and neither an Admin API request, an Aperture API request, nor a local CLI process is started

#### Scenario: Session identifiers do not transfer grants
- **WHEN** requests from callers with different grants reuse a session identifier, including across `/mcp` and `/tailscale/mcp`
- **THEN** each list and call is evaluated against the current request's trusted grants, not the previous caller's permissions

### Requirement: Catalog state is complete and server-local
The system SHALL maintain one catalog per server with exactly one metadata entry for each registered tool and no entries for absent tools. Catalog read-only metadata SHALL agree with MCP annotations. Construction SHALL reject duplicate names or incomplete metadata, and constructing another server SHALL NOT alter existing servers' authorization.

#### Scenario: All registration layers are included
- **WHEN** core, generated, special network-flow-log, and curated tools are registered
- **THEN** catalog names exactly equal registered tool names and each entry has a valid group and matching read-only metadata

#### Scenario: Optional local CLI tools are disabled
- **WHEN** local CLI opt-in is absent
- **THEN** local diagnostic tools are absent from both registration and catalog and no selector enables them

#### Scenario: Servers have independent tool surfaces
- **WHEN** two servers with different optional tool configurations are constructed concurrently
- **THEN** their catalogs and authorization remain independent without data races

### Requirement: Tool metadata is inspectable without credentials
The system SHALL provide a deterministic `--list-groups` listing of tool names, groups, and read-only classification for the configured tool surface without requiring credentials, a tailnet, or network access. It SHALL include Tailscale only when boolean `--tailscale` / `TS_MCP_TAILSCALE` is true (default true), and Aperture only when boolean `--aperture` / `TS_MCP_APERTURE` is true (default false) and `--stdio` is absent. Explicit flags SHALL override environment values, including `--tailscale=false` and `--aperture=false` overriding environment values of true; a URL alone SHALL NOT enable Aperture. Stdio SHALL ignore Aperture for listing and include Tailscale only when enabled. Informational listing SHALL bypass serving-mode validation and permit both services disabled, returning `[]` when neither service is included, including `--stdio --tailscale=false --aperture`. The existing JSON entry shape SHALL remain unchanged. Documentation SHALL explain OR semantics, sensitive read access, future selector expansion, unchanged Tailscale exact grant names, and broad selectors' inclusion of Aperture tools only when enabled in HTTP mode.

#### Scenario: Operator inspects Aperture-only groups offline
- **WHEN** `--list-groups --tailscale=false --aperture` runs with `TS_MCP_TAILSCALE=true` and without credentials or tailnet configuration
- **THEN** only Aperture metadata is listed without initializing Admin API clients, tsnet, or upstream clients, and without network access

#### Scenario: Operator disables both services for inspection
- **WHEN** `--list-groups --tailscale=false --aperture=false` runs without credentials or tailnet configuration
- **THEN** it prints `[]` and exits successfully offline rather than applying the no-services serving error

#### Scenario: Stdio inspection ignores Aperture with Tailscale disabled
- **WHEN** `--list-groups --stdio --tailscale=false --aperture` runs
- **THEN** it prints `[]` and exits successfully offline rather than applying the stdio serving error

#### Scenario: Operator inspects groups offline
- **WHEN** `--list-groups` runs with Tailscale enabled and without Aperture opt-in, credentials, or tailnet configuration
- **THEN** it prints deterministic metadata for Tailscale only and exits successfully without initializing tsnet, fetching a schema, or constructing clients that perform network requests

#### Scenario: Operator inspects enabled Aperture groups offline
- **WHEN** `--list-groups --aperture` or `--list-groups` with `TS_MCP_APERTURE=true` runs with Tailscale enabled and without stdio, credentials, or tailnet configuration
- **THEN** it prints deterministic metadata for both services and exits successfully without initializing tsnet, fetching a schema, or making upstream calls

#### Scenario: Operator disables environment-enabled Aperture for inspection
- **WHEN** `--list-groups --aperture=false` runs with Tailscale enabled, `TS_MCP_APERTURE=true`, and a malformed Aperture URL
- **THEN** only Tailscale metadata is listed without validating the URL or constructing an Aperture client

#### Scenario: URL alone does not expand offline metadata
- **WHEN** `--list-groups` runs with Tailscale enabled and an Aperture URL but no Aperture opt-in
- **THEN** only Tailscale metadata is listed, even if the URL is malformed

#### Scenario: Operator inspects stdio groups
- **WHEN** `--list-groups --stdio` runs with Tailscale enabled, even with `--aperture` or `TS_MCP_APERTURE=true` and a malformed Aperture URL
- **THEN** only the preserved Tailscale tool metadata is listed

### Requirement: Core handlers fail safely
The system SHALL reject missing, non-string, or blank `get_device_info` device arguments without panicking or contacting the Admin API. Tool and resource handler panics SHALL be recovered into sanitized failures without terminating the server or exposing stack traces or credentials to clients.

#### Scenario: Device argument is invalid
- **WHEN** an authorized caller supplies a missing, numeric, object, or blank device argument
- **THEN** the tool returns an input error and makes no Admin API call

#### Scenario: Handler panics
- **WHEN** a tool or resource handler panics
- **THEN** the caller receives a sanitized failure and subsequent MCP requests can still be served

### Requirement: Lifecycle tools use a separate organizations group
The system SHALL register the three lifecycle tools in trusted group `organizations`, with only `tailscale_list_organization_tailnets` classified as read-only. Exact tool names in `jaxxstorm.com/cap/mcp` tool grants SHALL authorize only their matching tools. OAuth scopes SHALL NOT establish MCP caller permissions. Existing `group:tailnet` SHALL NOT authorize any of these tools.

#### Scenario: Read selectors are used
- **WHEN** a caller has only `read:*` or `group:organizations:read`
- **THEN** the caller can discover and invoke organization listing but cannot discover or invoke creation or deletion

#### Scenario: Lifecycle group grants mutations
- **WHEN** a caller has `group:organizations`
- **THEN** all three lifecycle tools are authorized, while creation still requires operation confirmation and deletion still requires matching target acknowledgement and confirmation

#### Scenario: An exact grant is used
- **WHEN** a caller has only `tailscale_create_organization_tailnet` in its tools grant
- **THEN** only creation is authorized among the lifecycle tools and listing and deletion remain denied

#### Scenario: Existing tailnet group or upstream scope is insufficient
- **WHEN** a caller has only `group:tailnet` or lacks MCP grants despite the server credential having upstream `all` scope
- **THEN** lifecycle calls are denied before upstream access and the tools are absent from that caller's discovery result

### Requirement: Lifecycle permissions remain discoverable and fail closed
Lifecycle tools SHALL participate in the server-local catalog, offline group listing, request-specific discovery filtering, and handler-level authorization. Documentation SHALL distinguish exact grants, broad selectors, and upstream OAuth scope requirements, and warn that creation output contains sensitive credentials. Permission denial SHALL occur before any lifecycle API call.

#### Scenario: Unauthorized direct lifecycle invocation
- **WHEN** an ungranted caller directly invokes any lifecycle tool with valid inputs and confirmations
- **THEN** the invocation fails without contacting Tailscale

#### Scenario: Operator inspects lifecycle metadata offline
- **WHEN** `--list-groups` runs without credentials or network access
- **THEN** the three tools appear once each in `organizations` with read-only flags consistent with their MCP annotations

### Requirement: Aperture permissions use distinct names and existing selector semantics
When enabled in HTTP mode, Aperture tools SHALL use exact `aperture_*` names and groups `aperture-config` and `aperture-pricing` under `jaxxstorm.com/cap/mcp`. Existing exact Tailscale names and groups SHALL NOT authorize Aperture tools. Broad selectors SHALL retain their existing meaning: `*` includes all registered tools and `read:*` includes registered Aperture readers and non-mutating validation but excludes configuration replacement. Aperture tools SHALL be absent from registration and catalogs when disabled or in stdio; wildcard, group, and exact grants SHALL NOT enable them. `group:aperture-config:read` SHALL exclude replacement, while `group:aperture-config` SHALL include it subject to confirmation and concurrency safeguards. The grant schema SHALL remain unchanged for tailnet and local grants. Missing or malformed grants SHALL remain fail-closed.

#### Scenario: Grants do not enable disabled Aperture
- **WHEN** Aperture is disabled or stdio is selected and tailnet or local grants contain `*`, `read:*`, Aperture groups, or exact Aperture names
- **THEN** no Aperture tools appear in registration, catalogs, or discovery, no Aperture API call is made, and Tailscale permissions remain unchanged

#### Scenario: Enabling Aperture expands wildcard access
- **WHEN** Aperture is enabled in HTTP mode for callers with existing wildcard tool grants
- **THEN** `*` includes all five Aperture tools and `read:*` includes its four non-mutating tools, while replacement still requires confirmation and a concrete ETag

#### Scenario: Caller has only Tailscale grants
- **WHEN** a caller with only exact Tailscale permissions or Tailscale group selectors requests Aperture discovery or execution
- **THEN** no Aperture tool is authorized and no Aperture API request is made

#### Scenario: Caller has an exact Aperture grant
- **WHEN** Aperture is enabled in HTTP mode and a caller has only `aperture_get_config`
- **THEN** only that Aperture tool is discoverable and callable and no Tailscale tool is authorized by that grant

#### Scenario: Caller has read permissions
- **WHEN** a caller has `read:*` on the Aperture route
- **THEN** configuration read, validation, and both pricing tools are authorized but configuration replacement is not

#### Scenario: Caller has the configuration group
- **WHEN** Aperture is enabled in HTTP mode and a caller has `group:aperture-config`
- **THEN** configuration get, validation, and replacement are authorized while pricing remains denied and replacement still requires confirmation and a concrete ETag

#### Scenario: Grants are absent or malformed
- **WHEN** an Aperture request lacks trusted capabilities or contains malformed capability data
- **THEN** no Aperture operation is authorized and malformed capability data rejects the request before backend access

### Requirement: Upstream Aperture authority never substitutes for caller grants
The system SHALL enforce MCP caller grants independently of the MCP node's upstream Aperture roles. The deployment's upstream admin role and `read_pricing` permission SHALL NOT establish downstream caller permissions. Documentation SHALL state that upstream sees the MCP node rather than the original MCP caller and SHALL recommend auditing broad grants before enabling Aperture.

#### Scenario: Privileged backend identity receives an ungranted call
- **WHEN** the MCP node has upstream admin and pricing access but the caller lacks the tool grant
- **THEN** the tool is hidden and direct invocation is denied before upstream access

#### Scenario: Caller grant exceeds upstream role
- **WHEN** a caller has an MCP tool grant but the MCP node lacks the required upstream permission
- **THEN** the tool returns the upstream authorization failure without falling back to another identity or expanding grants
