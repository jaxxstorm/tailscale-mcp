## ADDED Requirements

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
