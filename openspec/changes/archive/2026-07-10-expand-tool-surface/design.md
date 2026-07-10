## Context

The project already exposes the full vendored Tailscale OpenAPI snapshot as generated tools/resources plus a small set of hand-written core tools. That satisfies API parity, but it leaves many workflows with raw operation names and generic `body` inputs. The YawLabs tool surface shows a useful complementary layer: curated tools with task-oriented names, stronger input schemas, composed status responses, ACL-specific HuJSON/ETag handling, and optional local CLI diagnostics.

This change should add that ergonomic layer without deleting or renaming existing generated tools. Existing generated tools remain the canonical OpenAPI parity surface and coverage source of truth.

## Goals / Non-Goals

**Goals:**

- Add curated operator-facing tools for common Tailscale workflows while preserving generated tool coverage.
- Reuse existing Admin API authentication, generic request execution, grant checks, confirmation checks, and MCP hint conventions.
- Add local CLI diagnostics only when explicitly enabled by configuration.
- Keep coverage totals stable and prevent curated wrappers from double-counting OpenAPI parity.
- Document curated tools as an ergonomic layer over the raw endpoint surface.

**Non-Goals:**

- Replacing generated `tailscale_<operation>` tools.
- Implementing every YawLabs tool verbatim or copying TypeScript code.
- Adding write access without existing MCP grants and explicit confirmation tokens.
- Making local CLI tools available by default.
- Changing transport, credential, tsnet startup, or existing resource URI behavior.

## Decisions

1. Put curated tools in a dedicated package.

   Add an internal package such as `internal/curatedtools` that registers task-oriented tool groups. It should accept the existing typed Admin API client where useful, the generic `readapi.Client` for broad JSON requests, and the existing `checkToolAccess` function. This keeps `main.go` as wiring and avoids mixing all curated handlers into the root package.

   Alternative considered: add every curated tool directly to `main.go`. That is faster initially but makes the already-large file harder to test and reason about.

2. Keep generated tools authoritative for OpenAPI parity.

   Curated tools may call the same Tailscale Admin API operations, but coverage reports should continue to count the generated mapping once per OpenAPI operation. Curated tools should be documented and tested as aliases/compositions, not additional coverage units.

   Alternative considered: replace generated tool names with curated names. That would break grants and existing clients and would complicate coverage history.

3. Use task-oriented names and grants for curated tools.

   Curated tool names should describe operator intent, for example `tailscale_status`, `tailscale_get_acl`, `tailscale_update_acl`, `tailscale_deauthorize_device`, `tailscale_ping`, and `tailscale_netcheck`. Grant permissions should match the curated tool name under `jaxxstorm.com/cap/mcp`, while underlying generated tools keep their existing grant names.

   Alternative considered: reuse generated operation grant names for curated wrappers. That can be least-privilege for a single endpoint but becomes unclear for composed tools that call multiple endpoints.

4. Preserve server-side safeguards for writes.

   Every curated mutating tool should keep grant enforcement and require a `confirm` value. For single OpenAPI operation wrappers, the confirmation value should be the underlying OpenAPI operation ID. For composed/bulk curated tools, use the curated tool name as the confirmation token and document the underlying operations.

   Alternative considered: rely only on MCP `destructiveHint`/`idempotentHint`. Hints are advisory and not sufficient server-side protection.

5. Gate local CLI tools by explicit configuration.

   Add a disabled-by-default flag/env such as `TAILSCALE_LOCAL_CLI=1`. When disabled, local CLI tools should not be registered. When enabled, handlers must use `exec.CommandContext` with argument arrays, no shell, strict input validation, bounded output, and timeouts. Local CLI tools are read-only diagnostics only.

   Alternative considered: always register local CLI tools and fail at runtime if the binary is absent. That exposes misleading capabilities and weakens operator intent.

## Risks / Trade-offs

- Tool surface duplication may confuse users -> Document curated tools as ergonomic wrappers and keep generated tools visible for full API parity.
- Curated grants increase ACL policy size -> Use predictable names and document wildcard options for operators who want broad access.
- Bulk tools may partially fail -> Return structured per-item success/failure data rather than treating partial failures as total failure.
- Local CLI execution can be risky -> Keep local tools disabled by default, validate inputs, avoid shells, use timeouts, and mark them read-only.
- Coverage reports could double-count operations -> Keep curated tools out of OpenAPI coverage accounting and add tests for stable 90/90 coverage totals.

## Migration Plan

1. Add the curated tool package and registration hook in `main.go`.
2. Implement read-only status and ACL read/validate/preview tools first.
3. Add mutating ACL/device tools with confirmation and safety hints.
4. Add optional local CLI diagnostics behind `TAILSCALE_LOCAL_CLI`.
5. Add curated wrappers for remaining domains where they materially improve input schemas or naming.
6. Update docs and tests, then verify `go test ./...`, `go build ./...`, and `make coverage`.

Rollback is to stop registering curated tools and remove the new package/docs; generated OpenAPI coverage remains unchanged.

## Open Questions

- Which curated wrappers should be implemented first if scope must be reduced: local diagnostics, ACL workflows, or device workflows?
- Should composed status tools require a dedicated `tailscale_status` grant or accept access when the caller has all underlying endpoint grants?
