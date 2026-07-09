## ADDED Requirements

### Requirement: OpenAPI operations have explicit MCP mapping decisions
The system SHALL maintain a coverage record for each Tailscale OpenAPI operation that identifies whether the operation is exposed as an MCP tool, MCP resource, MCP prompt workflow, or explicit exclusion.

#### Scenario: Operation is represented in coverage inventory
- **WHEN** the coverage inventory is generated from the Tailscale OpenAPI document
- **THEN** every operation ID from the OpenAPI document appears exactly once with method, path, mapping type, status, and rationale

#### Scenario: Operation is intentionally excluded
- **WHEN** an operation is not exposed through MCP
- **THEN** the coverage record references an exclusion reason rather than leaving the operation as an unexplained gap

### Requirement: Read operations map to resources or tools based on MCP ergonomics
The system SHALL classify read-only Tailscale API operations as resources when they represent stable addressable state and as tools when they require parameters, search, filtering, pagination control, or broad client compatibility.

#### Scenario: Collection state is exposed as a resource
- **WHEN** a GET operation returns a stable collection such as devices or policy data
- **THEN** the mapping may expose a `tailscale://` resource URI with JSON content and a matching resource grant permission

#### Scenario: Parameterized read is exposed as a tool
- **WHEN** a GET operation requires an identifier, filter, pagination input, or lookup behavior
- **THEN** the mapping includes a typed MCP tool with explicit input schema and a tool grant permission

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
The system SHALL generate machine-readable and human-readable coverage reports showing implemented mappings, missing mappings, exclusions, and changes from an accepted baseline.

#### Scenario: Coverage gap report is generated
- **WHEN** the coverage command runs
- **THEN** it writes a JSON inventory and Markdown report grouped by API domain and mapping status

#### Scenario: Coverage baseline is compared
- **WHEN** a baseline file exists
- **THEN** the coverage command reports newly introduced gaps, closed gaps, and changed mapping decisions

### Requirement: Grant permissions are discoverable for every mapping
The system SHALL record the grant permission required for every API-backed MCP tool and resource mapping.

#### Scenario: Tool mapping includes grant permission
- **WHEN** an operation is mapped to an MCP tool
- **THEN** its coverage record includes the tool name and required permission under the `jaxxstorm.com/cap/mcp` capability model

#### Scenario: Resource mapping includes grant permission
- **WHEN** an operation is mapped to an MCP resource
- **THEN** its coverage record includes the resource URI or URI template and required permission under the `jaxxstorm.com/cap/mcp` capability model
