## Purpose

Define fail-closed MCP grant evaluation, caller-filtered discovery, and trusted tool metadata.

## Requirements

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
The system SHALL filter `tools/list` by the current request's grants and SHALL reject unauthorized `tools/call` before handler side effects. Handler-level permission checks SHALL remain authoritative in addition to SDK filtering, using the same evaluator and metadata. Permission denials SHALL be protocol errors or tool error results, never successful text results.

#### Scenario: Caller lists permitted tools
- **WHEN** a caller requests `tools/list`
- **THEN** every returned tool is authorized for that caller and ungranted tools are omitted

#### Scenario: Caller invokes an unlisted tool directly
- **WHEN** a caller submits `tools/call` for an ungranted tool with otherwise valid inputs and confirmation
- **THEN** the call fails and neither an Admin API request nor a local CLI process is started

#### Scenario: Session identifiers do not transfer grants
- **WHEN** requests from callers with different grants reuse a session identifier
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
The system SHALL provide a deterministic `--list-groups` listing of tool names, groups, and read-only classification for the configured tool surface without requiring credentials, a tailnet, or network access. Documentation SHALL explain OR semantics, sensitive read access, future selector expansion, and unchanged exact grant names.

#### Scenario: Operator inspects groups offline
- **WHEN** `--list-groups` runs without credentials or tailnet configuration
- **THEN** it prints deterministic metadata and exits successfully without initializing tsnet or Admin API clients that perform network requests

### Requirement: Core handlers fail safely
The system SHALL reject missing, non-string, or blank `get_device_info` device arguments without panicking or contacting the Admin API. Tool and resource handler panics SHALL be recovered into sanitized failures without terminating the server or exposing stack traces or credentials to clients.

#### Scenario: Device argument is invalid
- **WHEN** an authorized caller supplies a missing, numeric, object, or blank device argument
- **THEN** the tool returns an input error and makes no Admin API call

#### Scenario: Handler panics
- **WHEN** a tool or resource handler panics
- **THEN** the caller receives a sanitized failure and subsequent MCP requests can still be served
