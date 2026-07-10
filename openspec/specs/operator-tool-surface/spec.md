## Purpose

Define curated, task-oriented MCP tools for common Tailscale operator workflows.

## Requirements

### Requirement: Curated tools provide task-oriented operator workflows
The system SHALL expose curated MCP tools for common Tailscale operator tasks in addition to the generated OpenAPI endpoint tools.

#### Scenario: Curated read tool composes endpoint data
- **WHEN** an operator calls a curated read-only tool such as `tailscale_status`
- **THEN** the tool returns structured JSON composed from one or more Tailscale Admin API reads
- **AND** the tool metadata includes read-only, non-destructive, idempotent MCP hints

#### Scenario: Curated tool uses task-oriented schema
- **WHEN** a curated tool wraps an existing generated endpoint
- **THEN** the tool exposes named inputs for the operator task rather than requiring a generic `body` object when a clearer schema is practical

### Requirement: Curated tools enforce MCP grants
The system SHALL require `jaxxstorm.com/cap/mcp` grants for every curated tool before reading Tailscale data or performing a mutation.

#### Scenario: Curated tool grant is checked
- **WHEN** a caller invokes a curated tool
- **THEN** access is checked against the curated tool name as the required grant permission

#### Scenario: Composed curated tool has one grant
- **WHEN** a curated tool composes multiple Admin API calls
- **THEN** the tool requires its curated tool grant before performing any underlying API call

### Requirement: Curated mutating tools require confirmation
The system SHALL require explicit confirmation for every curated tool that mutates Tailscale state.

#### Scenario: Single-operation curated mutation requires operation confirmation
- **WHEN** a curated mutating tool wraps one Tailscale OpenAPI operation
- **THEN** the tool requires a `confirm` argument whose value is the underlying OpenAPI operation ID

#### Scenario: Composed curated mutation requires curated confirmation
- **WHEN** a curated mutating tool performs multiple underlying operations or a bulk workflow
- **THEN** the tool requires a `confirm` argument whose value is the curated tool name

#### Scenario: Curated destructive tool advertises safety hints
- **WHEN** a curated tool can delete, deauthorize, expire, suspend, rotate, or otherwise destructively change Tailscale state
- **THEN** the tool metadata includes `destructiveHint=true`

### Requirement: ACL tools preserve policy safety
The system SHALL expose curated ACL tools that preserve HuJSON policy text, validate or preview policies without mutation, and update policies safely.

#### Scenario: ACL read returns update token
- **WHEN** an operator calls `tailscale_get_acl`
- **THEN** the tool returns the current policy text and the ETag needed for a safe update

#### Scenario: ACL validation does not mutate policy
- **WHEN** an operator calls `tailscale_validate_acl` or `tailscale_preview_acl`
- **THEN** the tool does not change the tailnet policy
- **AND** the tool metadata advertises read-only behavior

#### Scenario: ACL update requires ETag and confirmation
- **WHEN** an operator calls `tailscale_update_acl`
- **THEN** the tool requires the full policy text, the previous ETag, and a confirmation token before updating the policy

### Requirement: Device workflow tools expose ergonomic operations
The system SHALL expose curated device tools for common lifecycle, route, tag, IP, key, and posture attribute workflows.

#### Scenario: Device read workflow is available
- **WHEN** an operator needs to list or inspect devices, routes, or posture attributes
- **THEN** curated read-only device tools return structured JSON with task-oriented names and schemas

#### Scenario: Device mutation workflow is guarded
- **WHEN** an operator authorizes, deauthorizes, deletes, renames, expires, tags, routes, changes IP, or updates posture attributes for a device
- **THEN** the curated tool requires the relevant grant, explicit confirmation, and safety hints matching the operation risk

#### Scenario: Bulk device workflow reports partial failures
- **WHEN** a curated bulk device tool updates multiple devices and some updates fail
- **THEN** the response includes per-device success and failure details without hiding partial success

### Requirement: Local CLI diagnostics are opt-in
The system SHALL expose local Tailscale CLI diagnostic tools only when explicitly enabled by operator configuration.

#### Scenario: Local CLI tools are disabled by default
- **WHEN** the server starts without the local CLI opt-in configuration
- **THEN** local diagnostic tools such as `tailscale_local_status`, `tailscale_ping`, `tailscale_netcheck`, and `tailscale_local_version` are not registered

#### Scenario: Local CLI tools run safely when enabled
- **WHEN** local CLI tools are enabled and invoked
- **THEN** commands are executed without a shell, with validated inputs, bounded output, and context timeouts
- **AND** tools are marked read-only, non-destructive, and idempotent

### Requirement: Curated domain wrappers improve common Admin API areas
The system SHALL add curated wrappers for DNS, invites, keys, logging, posture, services, tailnet settings, users, and webhooks when they provide clearer names, safer schemas, or composed responses compared to raw generated endpoints.

#### Scenario: Domain wrapper preserves underlying API access
- **WHEN** a curated domain wrapper is added for an existing Admin API operation
- **THEN** the generated endpoint tool remains available with its existing name, grant, confirmation, and safety hints

#### Scenario: Domain wrapper documents underlying operation
- **WHEN** curated tool documentation lists a domain wrapper
- **THEN** it identifies the operator task, required curated grant, and whether the tool reads or mutates Tailscale state
