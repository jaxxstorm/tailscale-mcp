## MODIFIED Requirements

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
