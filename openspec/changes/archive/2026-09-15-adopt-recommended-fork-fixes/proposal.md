## Why

The fork identifies real build, authorization, local transport, and credential-lifetime defects in upstream. Selectively adopting its improvements with the review's security and lifecycle corrections will make existing MCP operations usable and safer without importing runtime secrets or breaking tool identities.

## What Changes

- Align gVisor with the pinned Tailscale release and derive release CI's Go toolchain from `go.mod`; add build/test verification for pull requests.
- Parse and union all `jaxxstorm.com/cap/mcp` entries using typed request context, failing closed on malformed capabilities.
- **BREAKING**: Replace implicit resource-prefix authorization with exact URI matching and explicit trailing `/*` descendants; empty strings never authorize resources. Existing prefix-based policies need migration.
- Add explicit local grants for stdio and separately opt-in loopback HTTP with its own port. **BREAKING**: Do not open the previously unconditional localhost listener by default.
- Add optional tailnet HTTPS, refreshable federated `idTokenFile` support, bounded credential validation, and credential-free version/catalog inspection.
- Harden origins, request bodies, handler failures, input validation, and two-listener shutdown, including nonzero exit on serving failure.
- Filter tool discovery and calls by grants; add `read:*`, `group:<name>`, and `group:<name>:read` selectors backed by server-owned registration metadata and a credential-free `--list-groups` command.
- Preserve exact tool names, curated wrappers, resource URIs, mutation confirmations, and canonical API coverage. Document selector expansion and local trust boundaries.
- Exclude URL profiles, profile configuration, wrapper deletion, fork planning documents, and all fork runtime/state/key artifacts. Preserve attribution for selectively ported source.

## Capabilities

### New Capabilities
- `mcp-grant-authorization`: Unioned capabilities, exact resource authorization, tool selectors and filtered discovery, server-local metadata, and safe denial/input behavior.
- `build-release-validation`: Dependency/toolchain alignment, automated verification, and exclusion of runtime credentials from integration.

### Modified Capabilities
- `mcp-streamable-http-transport`: Explicit local trust configuration, optional TLS, strict origin validation, bounded requests, and coordinated lifecycle handling while retaining deprecated stdio.
- `single-oauth-credential-startup`: Refreshable federated assertions, bounded validation, transport-specific tsnet requirements, and offline informational commands.

## Impact

All currently mapped Tailscale OpenAPI areas remain in scope for cross-cutting authorization and transport behavior: devices, policy/ACLs, DNS, invites, keys, logging, posture, services, tailnet settings, users, webhooks, and other existing mappings. Existing reads remain tools and/or resources; mutations remain explicitly confirmed tools. No new OpenAPI endpoints or prompts are introduced; build, TLS, and credential changes add no MCP primitive.

Affected code includes `main.go`, registration in `internal/readapi` and `internal/curatedtools`, new focused authorization/catalog/transport helpers, credential and transport tests, `go.mod`/`go.sum`, GitHub workflows, and operator documentation. Grants continue to use the existing capability key and exact permission identities; selectors add alternative ways to authorize those identities, not new Admin API scopes. Resource-prefix policies and localhost startup configuration require migration. Runtime secrets must never be imported, and existing tracked mappings and curated schemas must be retained.
