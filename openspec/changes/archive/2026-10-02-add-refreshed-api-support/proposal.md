## Why

The October 2 OpenAPI refresh increases the Tailscale v2 inventory from 90 to 93 operations, leaving organization listing, API-only tailnet creation, and tailnet deletion unavailable through MCP. Operators need explicit, grant-controlled access to these Alpha APIs without weakening existing authorization or destructive-action safeguards.

## What Changes

- Add the read-only `tailscale_list_organization_tailnets` tool for `listOrganizationTailnets` (`GET /organizations/{organization}/tailnets`), with typed pagination and complete upstream response data.
- Add the mutating `tailscale_create_organization_tailnet` tool for `createOrganizationTailnet` (`POST /organizations/{organization}/tailnets`), with required display name, operation confirmation, and sensitive one-time OAuth credential output.
- Add the destructive `tailscale_delete_tailnet` tool for `deleteTailnet` (`DELETE /tailnet/{tailnet}`), restricted to the explicitly configured tailnet and requiring matching target acknowledgement plus operation confirmation. Cross-tailnet credential exchange is not included.
- Classify all three tools in a new `organizations` group. Add exact tool grants under `jaxxstorm.com/cap/mcp`; only the listing tool qualifies for read selectors. Do not broaden `group:tailnet` to include deletion.
- Preserve and test existing JSON support for service `displayName`, CrowdStrike log streaming, new configuration-audit event/origin/actor values, and newly documented authorization/approval errors. These changes use existing tools/resources and grants, not new endpoint registrations.
- Regenerate coverage to report all 93 operations implemented and add a completeness regression check. No new resources, prompts, or curated aliases are needed.

## Capabilities

### New Capabilities

None. Extend the existing API and authorization capabilities.

### Modified Capabilities

- `tailscale-read-api-mcp`: Define the three lifecycle tools, their inputs, response handling, confirmations, deletion boundary, and refreshed-schema compatibility.
- `tailscale-api-mcp-mapping`: Define canonical lifecycle mappings and refreshed inventory completeness.
- `mcp-grant-authorization`: Define lifecycle group membership and exact/read/group authorization behavior.

## Impact

Changes affect `internal/readapi` endpoint metadata, registration, request validation/expansion, tests, the server catalog authorization tests, coverage checks and generated reports, and operator documentation. Preserve existing tool names, resources, grants, confirmations, stdio and tsnet HTTP behavior, and the single configured credential/startup model. Upstream OAuth scopes (`tailnets:read`, `tailnets`, and `all`) remain separate from MCP grants; organization-only credentials may still fail existing startup validation. Creation returns a sensitive OAuth secret to authorized callers only, without logging it. No SDK upgrade or general OpenAPI schema generator is required; existing audit-array typing and broad structured-error/reporting redesigns are outside this change.
