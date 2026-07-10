## 1. Curated Tool Infrastructure

- [x] 1.1 Create an `internal/curatedtools` package with registration entrypoints and shared handler helpers.
- [x] 1.2 Wire curated tool registration from `main.go` without changing generated `internal/readapi` tool/resource registration.
- [x] 1.3 Add shared helpers for structured JSON tool results, raw HuJSON responses, confirmation validation, and per-tool grant checks.
- [x] 1.4 Add tests that curated tools are registered with predictable names, grants, and MCP safety hints.

## 2. Status And ACL Tools

- [x] 2.1 Implement `tailscale_status` by composing tailnet device and settings reads into a concise health response.
- [x] 2.2 Implement `tailscale_get_acl` with raw HuJSON policy text and ETag exposure.
- [x] 2.3 Implement read-only `tailscale_validate_acl` and `tailscale_preview_acl` tools with HuJSON request handling.
- [x] 2.4 Implement guarded `tailscale_update_acl` requiring ETag and `confirm: "setPolicyFile"`.
- [x] 2.5 Add tests for ACL HuJSON handling, ETag propagation, confirmation enforcement, and read-only/mutating hints.

## 3. Device Workflow Tools

- [x] 3.1 Implement curated device read tools for list/get, routes, and posture attributes with task-oriented schemas.
- [x] 3.2 Implement guarded lifecycle tools for authorize, deauthorize, delete, rename, expire key, set routes, set tags, set IP, and update key settings.
- [x] 3.3 Implement posture attribute set/delete and batch posture attribute update with custom attribute validation.
- [x] 3.4 Implement a bulk device authorization tool that returns per-device success and failure details.
- [x] 3.5 Add tests for device input validation, confirmation behavior, partial failure output, grants, and safety hints.

## 4. Optional Local CLI Diagnostics

- [x] 4.1 Add disabled-by-default `TAILSCALE_LOCAL_CLI` / CLI configuration for local diagnostic tools.
- [x] 4.2 Implement safe local CLI execution using `exec.CommandContext`, argument arrays, no shell, bounded output, and timeouts.
- [x] 4.3 Register `tailscale_local_status`, `tailscale_ping`, `tailscale_netcheck`, and `tailscale_local_version` only when local CLI tools are enabled.
- [x] 4.4 Add tests for disabled-by-default registration, ping target validation, timeout/error behavior, and read-only hints.

## 5. Additional Domain Wrappers

- [x] 5.1 Add curated DNS tools where named inputs improve over generic generated endpoint bodies.
- [x] 5.2 Add curated invite and key tools for common create/list/get/delete/update workflows with confirmations for mutations.
- [x] 5.3 Add curated logging, posture integration, service, tailnet settings, user, and webhook tools where they improve names, schemas, or composed responses.
- [x] 5.4 Add tests that each curated wrapper preserves the underlying generated endpoint tool and uses the curated grant name.

## 6. Coverage And Documentation

- [x] 6.1 Add coverage tests proving curated tools do not alter 90/90 OpenAPI mapping totals, generated tool names, resource URIs, or canonical grant names.
- [x] 6.2 Update `docs/usage.md` with curated tool groups, grant examples, confirmation rules, safety hints, and local CLI opt-in requirements.
- [x] 6.3 Update generated coverage documentation only if tooling output changes, without double-counting curated wrappers.

## 7. Verification

- [x] 7.1 Run `go test ./...`.
- [x] 7.2 Run `go build ./...`.
- [x] 7.3 Run `make coverage` and verify coverage remains 90 total, 90 implemented, 0 gaps, 0 excluded.
- [x] 7.4 Run `openspec status --change "expand-tool-surface"` and confirm artifacts are complete.
