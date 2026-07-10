## ADDED Requirements

### Requirement: Curated wrappers do not replace canonical OpenAPI mappings
The system SHALL keep generated OpenAPI mappings as the canonical operation coverage inventory even when curated tools wrap or compose the same Tailscale API operations.

#### Scenario: Curated wrapper is added for an implemented operation
- **WHEN** a curated tool wraps an operation already present in the OpenAPI coverage inventory
- **THEN** the generated operation mapping remains present and implemented
- **AND** the curated wrapper does not create a duplicate OpenAPI coverage record

#### Scenario: Coverage totals remain stable after curated tools
- **WHEN** curated tools are added without changing the vendored OpenAPI snapshot
- **THEN** coverage totals, generated tool names, resource URIs, mapping statuses, and grant names for canonical mappings remain unchanged
