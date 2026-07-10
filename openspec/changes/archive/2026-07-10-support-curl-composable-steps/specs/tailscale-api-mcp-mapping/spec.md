## ADDED Requirements

### Requirement: API-backed tools expose MCP safety hints
The system SHALL attach MCP tool annotations to API-backed tools so clients can distinguish read-only, idempotent, and destructive operations before invocation.

#### Scenario: Read endpoint tool advertises read-only behavior
- **WHEN** a Tailscale OpenAPI GET operation or read-like validation operation is exposed as an MCP tool
- **THEN** the tool metadata includes `readOnlyHint=true`, `destructiveHint=false`, and `idempotentHint=true`

#### Scenario: Destructive endpoint tool advertises destructive behavior
- **WHEN** a Tailscale OpenAPI operation deletes, revokes, expires, suspends, rotates, or otherwise destructively changes tailnet state
- **THEN** the tool metadata includes `destructiveHint=true`

#### Scenario: Idempotent write endpoint tool advertises idempotent behavior
- **WHEN** a Tailscale OpenAPI mutating operation can be safely repeated with the same inputs without creating additional side effects
- **THEN** the tool metadata includes `idempotentHint=true`

#### Scenario: Non-idempotent write endpoint tool does not claim idempotence
- **WHEN** a Tailscale OpenAPI mutating operation creates, sends, resends, rotates, tests, or otherwise performs an action that may cause repeated side effects
- **THEN** the tool metadata does not set `idempotentHint=true`

### Requirement: Client hints do not replace server-side mutation safeguards
The system SHALL keep grant enforcement and explicit confirmation requirements authoritative even when MCP safety hints are present.

#### Scenario: Mutating endpoint still requires confirmation
- **WHEN** a mutating Tailscale OpenAPI operation is exposed as an MCP tool with any combination of safety hints
- **THEN** the tool still requires the configured `confirm` argument whose value matches the OpenAPI operation ID

#### Scenario: Grant enforcement remains unchanged
- **WHEN** any API-backed tool or resource is invoked as part of an agent-composed workflow
- **THEN** access is still checked through the required `jaxxstorm.com/cap/mcp` tool or resource grant before accessing Tailscale data or performing a mutation

### Requirement: Endpoint primitives remain composable by agents
The system SHALL keep Tailscale OpenAPI reads and writes available as first-class MCP primitives so agents can synthesize multi-step workflows from individual endpoint calls.

#### Scenario: Agent composes read steps
- **WHEN** an agent needs to inspect tailnet state before deciding on a follow-up action
- **THEN** the relevant read endpoint is available as an MCP tool or resource with structured JSON output and a discoverable grant permission

#### Scenario: Agent composes guarded write steps
- **WHEN** an agent proposes a mutating follow-up action after one or more read steps
- **THEN** the mutating endpoint is available as a distinct MCP tool with safety hints, grant enforcement, and explicit confirmation input

### Requirement: Coverage validation includes safety hints
The system SHALL validate that every API-backed MCP tool mapping has safety hints consistent with its endpoint metadata.

#### Scenario: Coverage validation checks tool hints
- **WHEN** coverage validation runs against the Tailscale OpenAPI mapping inventory
- **THEN** every tool mapping has expected read-only, destructive, and idempotent hint metadata or an explicit endpoint-level override

#### Scenario: Coverage totals remain stable
- **WHEN** safety hint metadata is added to existing endpoint mappings
- **THEN** the operation coverage totals, mapping statuses, tool names, resource URIs, and grant names remain unchanged
