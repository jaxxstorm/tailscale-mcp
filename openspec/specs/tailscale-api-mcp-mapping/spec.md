## Purpose

Define how Tailscale OpenAPI operations are classified into MCP tools, resources, prompt workflows, or explicit exclusions, and how API coverage is tracked.

## Requirements

### Requirement: OpenAPI operations have explicit MCP mapping decisions
The system SHALL maintain a coverage record for each Tailscale OpenAPI operation that identifies whether the operation is exposed as an MCP tool, MCP resource, MCP prompt workflow, or explicit exclusion, and SHALL mark implemented endpoints as implemented when their MCP registration and grant enforcement exist.

#### Scenario: Operation is represented in coverage inventory
- **WHEN** the coverage inventory is generated from the Tailscale OpenAPI document
- **THEN** every operation ID from the OpenAPI document appears exactly once with method, path, mapping type, status, and rationale

#### Scenario: Operation is intentionally excluded
- **WHEN** an operation is not exposed through MCP
- **THEN** the coverage record references an exclusion reason rather than leaving the operation as an unexplained gap

#### Scenario: Operation is implemented
- **WHEN** an operation has an MCP tool or resource registered with grant enforcement
- **THEN** the coverage record marks it as implemented with the MCP name or URI and required grant permission

#### Scenario: Mutating operation includes confirmation metadata
- **WHEN** a mutating operation is implemented as an MCP tool
- **THEN** the coverage record includes the required confirmation token

### Requirement: Operations map to resources or tools based on MCP ergonomics
The system SHALL classify stable read-only Tailscale API operations as resources when they represent stable addressable state and as tools when they require parameters, search, filtering, pagination control, mutation, or broad client compatibility. In-scope gaps SHALL receive tool mappings first, with resources added for stable collection or entity state.

#### Scenario: Collection state is exposed as a resource
- **WHEN** a GET operation returns a stable collection such as devices or policy data
- **THEN** the mapping may expose a `tailscale://` resource URI with JSON content and a matching resource grant permission

#### Scenario: Parameterized read is exposed as a tool
- **WHEN** a GET operation requires an identifier, filter, pagination input, or lookup behavior
- **THEN** the mapping includes a typed MCP tool with explicit input schema and a tool grant permission

#### Scenario: In-scope gap is implemented
- **WHEN** a coverage gap is selected for implementation
- **THEN** the mapping includes at least a tool name, grant permission, and implementation rationale

### Requirement: Mutating operations map to explicit tools
The system SHALL classify every POST, PUT, PATCH, and DELETE Tailscale API operation as an MCP tool with typed inputs, operation-specific naming, and grant enforcement.

#### Scenario: Mutating endpoint is mapped
- **WHEN** a mutating OpenAPI operation is added to coverage
- **THEN** the mapping type is `tool`, the tool name describes the action and object, and the coverage record includes the required grant permission

#### Scenario: Destructive endpoint requires safe inputs
- **WHEN** a DELETE or otherwise destructive operation is mapped
- **THEN** the tool schema requires exact target identifiers and any additional confirmation fields defined by the mapping rules

### Requirement: Prompts represent workflows, not raw endpoint coverage
The system SHALL use MCP prompts only for higher-level operator workflows and SHALL NOT count a prompt alone as implementation coverage for an OpenAPI operation.

#### Scenario: Workflow prompt references tools and resources
- **WHEN** a prompt guides an operator through a Tailscale task
- **THEN** endpoint coverage is credited only to the underlying tools or resources used by that workflow

### Requirement: Coverage reports are generated and reviewable
The system SHALL generate machine-readable and human-readable coverage reports showing implemented mappings, missing mappings, exclusions, and changes from an accepted baseline, and transport changes SHALL NOT alter coverage status for existing OpenAPI operation mappings.

#### Scenario: Coverage gap report is generated
- **WHEN** the coverage command runs
- **THEN** it writes a JSON inventory and Markdown report grouped by API domain and mapping status

#### Scenario: Coverage baseline is compared
- **WHEN** a baseline file exists
- **THEN** the coverage command reports newly introduced gaps, closed gaps, and changed mapping decisions

#### Scenario: Transport changes preserve coverage
- **WHEN** MCP transport behavior changes without changing OpenAPI tool or resource mappings
- **THEN** coverage reports keep the same operation IDs, MCP names or URIs, grant permissions, confirmation metadata, and implementation statuses

### Requirement: Grant permissions are discoverable for every mapping
The system SHALL record the grant permission required for every API-backed MCP tool and resource mapping.

#### Scenario: Tool mapping includes grant permission
- **WHEN** an operation is mapped to an MCP tool
- **THEN** its coverage record includes the tool name and required permission under the `jaxxstorm.com/cap/mcp` capability model

#### Scenario: Resource mapping includes grant permission
- **WHEN** an operation is mapped to an MCP resource
- **THEN** its coverage record includes the resource URI or URI template and required permission under the `jaxxstorm.com/cap/mcp` capability model

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

### Requirement: Curated wrappers do not replace canonical OpenAPI mappings
The system SHALL keep generated OpenAPI mappings as the canonical operation coverage inventory even when curated tools wrap or compose the same Tailscale API operations.

#### Scenario: Curated wrapper is added for an implemented operation
- **WHEN** a curated tool wraps an operation already present in the OpenAPI coverage inventory
- **THEN** the generated operation mapping remains present and implemented
- **AND** the curated wrapper does not create a duplicate OpenAPI coverage record

#### Scenario: Coverage totals remain stable after curated tools
- **WHEN** curated tools are added without changing the vendored OpenAPI snapshot
- **THEN** coverage totals, generated tool names, resource URIs, mapping statuses, and grant names for canonical mappings remain unchanged
