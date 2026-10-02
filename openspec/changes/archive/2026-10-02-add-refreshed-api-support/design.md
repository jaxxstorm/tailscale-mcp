## Context

The refreshed vendored schema contains 93 operations on 60 paths; existing definitions map the original 90. Coverage reports are stale because `make openapi-refresh` updates only the snapshot and metadata. The new Alpha operations are `listOrganizationTailnets`, `createOrganizationTailnet`, and `deleteTailnet`.

The generic `internal/readapi` layer already handles HTTP calls, grants, confirmations, JSON responses, and coverage mappings. Its input metadata currently registers path/query values as strings and bodies as optional objects. Its group inference does not recognize either new path, and request expansion substitutes the configured tailnet before other parameters. Those constraints require explicit handling rather than simply appending definitions.

## Goals / Non-Goals

**Goals:** Expose all three operations as typed canonical tools, protect lifecycle actions, preserve refreshed response fields, and restore verified 93/93 operation coverage with discoverable permissions.

**Non-Goals:** Cross-tailnet token exchange, dynamic credentials, startup authentication changes, new resources/prompts/curated aliases, a general schema generator, fixing pre-existing audit-filter array typing, or redesigning all API errors and coverage baseline handling.

## Decisions

### Extend the existing generic endpoint layer narrowly

Add endpoint definitions and the minimum metadata/validation support for integer query bounds and a required typed body. Keep existing endpoint schemas unchanged. Prefer this to dedicated parallel HTTP handlers or wholesale generation because authorization, coverage, and transport behavior already share the generic layer.

| Tool | Inputs beyond existing grant context | Upstream behavior |
| --- | --- | --- |
| `tailscale_list_organization_tailnets` | Required nonblank string `organization`; optional integer `limit` in 1..100; optional string `cursor` | GET one page from `/organizations/{organization}/tailnets`; omit absent limit so upstream defaults to 100 |
| `tailscale_create_organization_tailnet` | Required nonblank string `organization`; required object `body` with required nonblank string `displayName`; `confirm=createOrganizationTailnet` | POST body to the same path; preserve the 200 JSON response |
| `tailscale_delete_tailnet` | Required nonblank string `tailnet` exactly matching explicit configured tailnet; `confirm=deleteTailnet` | DELETE `/tailnet/{tailnet}` without a body; accept empty 200 |

Escape organization as one path segment; permit the documented `-` organization shorthand. Do not add unsupported organization filters or automatically paginate: return `tailnets`, `cursor`, and `totalCount` unchanged so the caller controls each next page. A failed page returns an error, not a fabricated partial collection or continuation.

Creation returns `id`, `displayName`, `orgId`, `dnsName`, `createdAt`, `oauthClient`, and `alreadyExists` without discarding the one-time secret. Do not invent a display-name regex or borrow the unrelated service length constraint. Let upstream enforce uniqueness and documented naming rules. Do not automatically retry creation after an ambiguous failure.

### Restrict deletion to the configured target

Treat `tailnet` as explicit acknowledgement, not a request to switch authentication or override global configuration. Reject absent, blank, `-`, or mismatched targets and reject deletion when the configured tailnet is blank or `-`. Compare exact configured strings without fuzzy matching, aliases, or normalization. After grant, argument, and confirmation checks, use the configured client and target. This avoids the existing path-expansion substitution trap and accidental deletion of an implicit default.

Arbitrary-tailnet deletion was considered but would require a separate credential/token-exchange design. The server will not resolve names to IDs, infer a target from a previous creation result, accept per-call credentials, or switch tokens in this change. An upstream target-token mismatch remains a sanitized API error. Documentation must state that the configured credential needs authority for the configured deletion target.

### Use a distinct lifecycle authorization group

Explicitly map the three operation IDs to `organizations` in `internal/readapi/metadata.go`, including root tailnet deletion. Use their exact canonical tool names in capability `tools` arrays; coverage labels use `tool:<name>`. Do not use OAuth scopes as MCP grant names or place deletion in the existing `tailnet` group.

Listing has read-only/destructive/idempotent hints `true/false/true`; creation has `false/false/false`; deletion has `false/true/true`. Trusted catalog metadata must agree. `read:*` and `group:organizations:read` include listing only. `group:organizations` includes all three, with mutation confirmations still enforced. Existing global `*` selectors naturally include new tools; document this expansion and the sensitivity of organization listings and creation credentials.

### Preserve JSON compatibility and bounded error behavior

Existing raw JSON reads and body forwarding already accommodate service `displayName` (upstream maximum 64 characters), CrowdStrike log streaming, and new audit values. Add focused request/response regression tests rather than new tools or broad body-schema retrofits. Cover `GROUP.UPDATE.USER_ROLE`, the new PAM events, `BORDER0_API`, and PAM actor types through existing surfaces. Service resource responses also retain `displayName`.

Retain the generic sanitized handling of non-2xx statuses, including newly documented 400/402 responses. New lifecycle errors must satisfy the existing structured operation/status/message requirement, using a narrowly scoped adaptation if necessary; a repository-wide error-format migration is not required. Never include authorization headers, OAuth secrets, or arbitrary extra error fields in logs or failures. Return upstream errors without implying a successful creation/deletion or retrying lifecycle mutations. Success output containing one-time credentials is intentionally available only to authorized creation callers.

### Derive coverage from registrations

Use existing definition-derived mappings rather than duplicating a manual inventory. Regenerate JSON/Markdown/diff reports against the current snapshot after implementation. Add a test that inventories every snapshot operation and fails on gaps or missing registrations; check the three new mappings and retain the previous 90 names, URIs, grants, confirmations, and statuses. The snapshot-specific acceptance total is 93; do not freeze the general invariant to that count forever. Coverage counts operations, not schema fidelity, so schema regression tests remain separate.

## Risks / Trade-offs

- Alpha API contracts can change -> label tools and operator documentation accordingly and test against the vendored snapshot.
- Creation returns a powerful one-time secret -> limit through grants, avoid logs/error leakage, and warn operators about client transcript retention.
- Deletion is irreversible -> require exact configured-target acknowledgement, operation confirmation, destructive hints, and mock-only automated tests.
- Organization-only OAuth scopes can fail existing startup checks -> document `tailnets:read`, `tailnets`, and deletion's `all` scope separately from the unchanged startup requirements.
- Typed metadata could accidentally change existing inputs -> make extensions opt-in and exercise existing registrations, authorization, and coverage.
- Configured-target-only deletion is narrower than the raw endpoint -> document the restriction; defer cross-tailnet credentials rather than claiming implicit support.

## Migration Plan

No persisted-state migration is needed. Implement additive definitions and validators, run tests and coverage generation, and publish updated grant examples and credential warnings. Operators opt in with exact names or the new group; existing wildcard/read selectors expand according to their documented semantics. Rollback removes new registrations/group metadata and regenerates reports, leaving existing tools and grants unchanged. Rollback cannot undo an upstream tailnet creation or deletion.

## Open Questions

None blocking implementation. Cross-tailnet token exchange and broader schema/error conformance are separate future changes.
