## MODIFIED Requirements

### Requirement: Tool discovery and execution share authorization
The system SHALL filter `tools/list` by the current request's grants and SHALL reject unauthorized `tools/call` before handler side effects on both services, including both `/mcp` and `/tailscale/mcp` Tailscale aliases. The Tailscale aliases SHALL use identical grant enforcement on tailnet and explicitly enabled loopback, using identity-derived grants for tailnet and only operator-configured grants for loopback. Handler-level permission checks SHALL remain authoritative in addition to SDK filtering, using the same evaluator and the target service's metadata. Permission denials SHALL be protocol errors or tool error results, never successful text results.

#### Scenario: Caller lists permitted tools
- **WHEN** a caller requests `tools/list` on either service route
- **THEN** every returned tool is registered on that route and authorized for that caller and ungranted tools are omitted

#### Scenario: Caller invokes an unlisted tool directly
- **WHEN** a caller submits `tools/call` for an ungranted tool with otherwise valid inputs and confirmation
- **THEN** the call fails and neither an Admin API request, an Aperture API request, nor a local CLI process is started

#### Scenario: Session identifiers do not transfer grants
- **WHEN** requests from callers with different grants reuse a session identifier, including across `/mcp` and `/tailscale/mcp`
- **THEN** each list and call is evaluated against the current request's trusted grants, not the previous caller's permissions

### Requirement: Tool metadata is inspectable without credentials
The system SHALL provide a deterministic `--list-groups` listing of tool names, groups, and read-only classification for the configured tool surface without requiring credentials, a tailnet, or network access. HTTP configuration SHALL list both service catalogs while `--stdio` SHALL list only the Tailscale catalog. The existing JSON entry shape SHALL remain unchanged. Documentation SHALL explain OR semantics, sensitive read access, future selector expansion, unchanged Tailscale exact grant names, and broad selectors' inclusion of Aperture tools.

#### Scenario: Operator inspects groups offline
- **WHEN** `--list-groups` runs without credentials or tailnet configuration
- **THEN** it prints deterministic metadata for both services and exits successfully without initializing tsnet, fetching a schema, or constructing clients that perform network requests

#### Scenario: Operator inspects stdio groups
- **WHEN** `--list-groups --stdio` runs
- **THEN** only the preserved Tailscale tool metadata is listed

## ADDED Requirements

### Requirement: Aperture permissions use distinct names and existing selector semantics
Aperture tools SHALL use exact `aperture_*` names and groups `aperture-config` and `aperture-pricing` under `jaxxstorm.com/cap/mcp`. Existing exact Tailscale names and groups SHALL NOT authorize Aperture tools. Broad selectors SHALL retain their existing meaning: `*` includes all registered tools and `read:*` includes Aperture readers and non-mutating validation but excludes configuration replacement. `group:aperture-config:read` SHALL exclude replacement, while `group:aperture-config` SHALL include it subject to confirmation and concurrency safeguards. The grant schema SHALL remain unchanged for tailnet and local grants. Missing or malformed grants SHALL remain fail-closed.

#### Scenario: Caller has only Tailscale grants
- **WHEN** a caller with only exact Tailscale permissions or Tailscale group selectors requests Aperture discovery or execution
- **THEN** no Aperture tool is authorized and no Aperture API request is made

#### Scenario: Caller has an exact Aperture grant
- **WHEN** a caller has only `aperture_get_config`
- **THEN** only that Aperture tool is discoverable and callable and no Tailscale tool is authorized by that grant

#### Scenario: Caller has read permissions
- **WHEN** a caller has `read:*` on the Aperture route
- **THEN** configuration read, validation, and both pricing tools are authorized but configuration replacement is not

#### Scenario: Caller has the configuration group
- **WHEN** a caller has `group:aperture-config`
- **THEN** configuration get, validation, and replacement are authorized while pricing remains denied and replacement still requires confirmation and a concrete ETag

#### Scenario: Grants are absent or malformed
- **WHEN** an Aperture request lacks trusted capabilities or contains malformed capability data
- **THEN** no Aperture operation is authorized and malformed capability data rejects the request before backend access

### Requirement: Upstream Aperture authority never substitutes for caller grants
The system SHALL enforce MCP caller grants independently of the MCP node's upstream Aperture roles. The deployment's upstream admin role and `read_pricing` permission SHALL NOT establish downstream caller permissions. Documentation SHALL state that upstream sees the MCP node rather than the original MCP caller and SHALL recommend auditing broad grants before enabling the new version.

#### Scenario: Privileged backend identity receives an ungranted call
- **WHEN** the MCP node has upstream admin and pricing access but the caller lacks the tool grant
- **THEN** the tool is hidden and direct invocation is denied before upstream access

#### Scenario: Caller grant exceeds upstream role
- **WHEN** a caller has an MCP tool grant but the MCP node lacks the required upstream permission
- **THEN** the tool returns the upstream authorization failure without falling back to another identity or expanding grants
