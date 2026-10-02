## ADDED Requirements

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
