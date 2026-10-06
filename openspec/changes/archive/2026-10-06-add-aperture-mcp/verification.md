# Implementation Verification

## Results

- `go test ./...`: passed for all packages, including protocol, startup, cached-contract, client, and refresh tests.
- `go test -race ./...`: passed for all packages.
- `make coverage`: passed; Tailscale coverage remains 93 total operations, 93 implemented, 0 gaps, 0 excluded.
- Aperture production contract coverage: passed; all five cached operations match production tool registrations, exact names, groups, and read-only classifications. Snapshot metadata and SHA-256 are independently checked offline.
- `openspec validate add-aperture-mcp --strict`: passed.
- `git diff --check`: passed.

All automated verification uses cached schema data and mocked upstreams. The initial schema was downloaded from the tailnet-only source during artifact creation; implementation tests do not fetch it.

The optional live non-mutating smoke test was skipped because no deployed MCP node with confirmed Aperture admin / `read_pricing: true` authority and corresponding MCP caller grants was established for this session. Mocked tsnet-dialer integration tests verify the outbound identity transport, base path, grant separation, and behavior when Aperture is unavailable. No live configuration replacement was performed.

## Revised Alias Requirement

Existing HTTP clients using `/mcp` continue to work. `/tailscale/mcp` is the preferred explicit route; both paths must dispatch without redirects to the same Tailscale handler, server, catalog, and session state, with identical grants and transport protections on tailnet and explicitly enabled loopback. Shared sessions never transfer grants: every request uses its current trusted grant source. Aperture remains a separate server at `/aperture/mcp` on the same port, with separate catalog and session state. Audit existing broad `*` / `read:*` grants before deployment because they include matching Aperture tools.

After implementing the alias, `go test ./...`, `go test -race ./...`, `openspec validate add-aperture-mcp --strict`, and `git diff --check` passed again. Protocol tests verify direct alias handling, shared Tailscale sessions in both directions, per-request authorization and equal protections on both listener types, and unchanged Aperture isolation. The production-stack test also verifies the alias remains available when Aperture is unavailable.

## Archive Verification

On 2026-10-06, reran `go test ./...`, `go test -race ./...`, and `make coverage` successfully after the alias changes. Tailscale coverage remains 93/93 operations. Synced all three delta specs into the main specifications; `openspec validate --specs --strict` passed all eight main specs. Reconciled task 7.6 and removed stale pending-verification notes before archiving.
