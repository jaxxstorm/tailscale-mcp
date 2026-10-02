## Purpose

Define reproducible builds, API-preserving verification, and credential-free release contents.

## Requirements

### Requirement: Builds align with the pinned Tailscale toolchain and dependency graph
The project SHALL use a gVisor revision compatible with its pinned Tailscale module and SHALL derive the CI Go version from `go.mod` for verification and releases rather than maintaining a conflicting hard-coded version.

#### Scenario: Clean checkout builds
- **WHEN** dependencies are resolved for the pinned module graph and `go build ./...` runs with the declared toolchain
- **THEN** the project builds without the incompatible gVisor package errors identified in the fork review

#### Scenario: Module Go version changes
- **WHEN** the required Go version in `go.mod` changes
- **THEN** verification and release workflows select that version without a separate workflow version edit

### Requirement: Automated verification protects the existing API surface
The project SHALL run build, tests, and coverage verification on pull requests and before publishing releases. Verification SHALL preserve the canonical OpenAPI operation IDs, tool names, resource URIs, exact grant identities, confirmation metadata, and implementation statuses. It SHALL NOT treat caller-filtered discovery as reduced endpoint coverage.

#### Scenario: Verification fails
- **WHEN** a build, test, or coverage validation fails
- **THEN** the verification workflow fails and a release workflow does not publish artifacts from that failed run

#### Scenario: Coverage is regenerated after selective integration
- **WHEN** coverage is regenerated after this change
- **THEN** all existing canonical mappings remain implemented with unchanged identities and confirmation metadata, and curated wrappers remain registered

### Requirement: Fork integration excludes runtime credentials
The integration SHALL include only reviewed source, tests, and relevant operator documentation with source attribution. It SHALL NOT import fork runtime state, private keys, certificates, logs, or unrelated planning documents. Runtime tsnet directories SHALL be ignored for new untracked files and excluded from release artifacts.

#### Scenario: Integration and package contents are reviewed
- **WHEN** the changed-file list, tracked files, and release package contents are inspected
- **THEN** no fork runtime/state/key artifacts are present and the source of ported changes is documented
