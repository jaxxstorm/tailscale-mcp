## ADDED Requirements

### Requirement: Organization lifecycle operations have canonical mappings
The system SHALL map `listOrganizationTailnets`, `createOrganizationTailnet`, and `deleteTailnet` to `tailscale_list_organization_tailnets`, `tailscale_create_organization_tailnet`, and `tailscale_delete_tailnet`, respectively. Each mapping SHALL name its exact tool grant and Alpha status; creation and deletion SHALL record confirmation tokens equal to their operation IDs. No new resource or prompt mapping SHALL substitute for these tools.

#### Scenario: Lifecycle mappings are generated
- **WHEN** coverage is regenerated from registered endpoint definitions
- **THEN** each lifecycle operation appears exactly once as implemented with its method, path, canonical tool, `tool:<canonical-name>` grant label, rationale, and applicable confirmation

#### Scenario: Safety hints are inspected
- **WHEN** clients inspect lifecycle tool annotations
- **THEN** listing has read-only/destructive/idempotent hints true/false/true, creation has false/false/false, and deletion has false/true/true

### Requirement: Refreshed snapshot coverage is verified for completeness
Automated coverage validation SHALL check every operation in the vendored snapshot and fail on unexplained gaps or claimed implementations without registrations. For the October 2 refresh, reports SHALL contain 93 implemented operations with zero gaps or exclusions, preserving existing operation identities, mapping names, resource URIs, grants, confirmations, and statuses for the original 90 operations.

#### Scenario: Refreshed coverage is generated
- **WHEN** `make coverage` runs after lifecycle implementation
- **THEN** the machine-readable and human-readable reports describe all 93 operations, including the three new mappings, without changing the original 90 mappings

#### Scenario: A future refresh adds an unmapped operation
- **WHEN** the vendored snapshot contains an operation with neither an implemented mapping nor an explicit justified exclusion
- **THEN** automated coverage validation fails rather than only checking already registered mappings
