## Why

The coverage report identified uncovered Tailscale OpenAPI operations, so operators could not manage the full Admin API surface through MCP. Implementing full coverage closes the parity gap while requiring explicit confirmation for mutating operations.

## What Changes

- Add MCP tools for all remaining Tailscale OpenAPI gaps across Contacts, DNS, DeviceInvites, DevicePosture, Devices, Keys, Logging, OAuthApps, PolicyFile, Services, TailnetSettings, UserInvites, Users, and Webhooks.
- Add MCP resources for stable collection/entity state where useful, such as DNS configuration, keys, users, webhooks, services, invites, device routes, posture integrations, and logs.
- Update coverage mappings so all OpenAPI operations move from `gap` to `implemented` with grant names and MCP names/URIs.
- Require mutating operations (`POST`, `PUT`, `PATCH`, `DELETE`) to include an explicit confirmation token matching the OpenAPI operation ID.
- Preserve grant enforcement for every new tool and resource using the existing `jaxxstorm.com/cap/mcp` capability envelope.
- Update README and generated coverage reports to document new tools, resources, and required grants.

## Capabilities

### New Capabilities

- `tailscale-read-api-mcp`: Exposes Tailscale OpenAPI operations as MCP tools and resources, with grant enforcement, mutating-operation confirmation, and coverage tracking.

### Modified Capabilities

- `tailscale-api-mcp-mapping`: Updates coverage mapping requirements to account for implemented tools/resources and mutating-operation confirmation metadata.

## Impact

- Affects MCP server registration and likely requires splitting current `main.go` registration into smaller tool/resource helpers.
- Affects Tailscale API client usage for endpoint groups not currently covered by the typed Go client.
- Affects grant permission documentation and coverage metadata under `tools/coverage` and generated reports under `coverage/`.
- Implements mutating API actions as guarded tools requiring both MCP grants and operation-ID confirmation.
