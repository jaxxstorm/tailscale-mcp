## MODIFIED Requirements

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
