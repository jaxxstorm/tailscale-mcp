## 1. Lifecycle Input Support

- [x] 1.1 Extend `internal/readapi/types.go` and registration narrowly for opt-in integer query parameters with bounds and required object bodies with required string properties, preserving existing endpoint schemas.
- [x] 1.2 Add input-schema and handler validation tests through the production MCP registration path for nonblank strings, integer bounds, wrong types, missing bodies/properties, and zero upstream calls on invalid inputs.

## 2. Organization Listing and Creation

- [x] 2.1 Define and register `tailscale_list_organization_tailnets` with organization, integer limit 1..100, and cursor; test escaped organization paths, `-`, omitted/default pagination, valid boundaries, one-page behavior, and complete response metadata.
- [x] 2.2 Define and register `tailscale_create_organization_tailnet` with required body/displayName and `confirm=createOrganizationTailnet`; test exact POST/body, 200 responses, missing/wrong confirmation, and preservation of all response fields including one-time credentials and `alreadyExists`.
- [x] 2.3 Ensure new lifecycle API failures expose sanitized structured operation/status/message information, do not trigger mutation retries, and do not leak authorization headers or OAuth secrets into errors or logs; add mocked failure and captured-log tests.

## 3. Configured Tailnet Deletion

- [x] 3.1 Define and register `tailscale_delete_tailnet` with exact configured-target acknowledgement and `confirm=deleteTailnet`; reject missing, blank, non-string, `-`, and mismatched targets before path expansion or upstream access.
- [x] 3.2 Add mock-only deletion tests proving exact DELETE path, no body, configured credential reuse, empty 200 success, no token exchange, safe upstream failure, and zero requests for invalid targets or confirmations.

## 4. Lifecycle Grants and Discovery

- [x] 4.1 Classify all three operation IDs in `organizations` and set read-only/destructive/idempotent annotations to listing true/false/true, creation false/false/false, and deletion false/true/true; test catalog completeness and construction.
- [x] 4.2 Add catalog and handler tests for exact grants, `*`, `read:*`, `group:organizations`, and `group:organizations:read`, proving caller-filtered discovery, direct-call denial, and confirmation enforcement for authorized mutations.
- [x] 4.3 Test that `group:tailnet` and upstream OAuth scopes alone do not grant lifecycle access, and verify deterministic credential-free `--list-groups` output includes the three tools with correct metadata.

## 5. Existing Schema Compatibility

- [x] 5.1 Add service regression tests preserving `displayName` across list/get/update tools and existing service resource responses without changing grants or body-forwarding compatibility.
- [x] 5.2 Add log-streaming tests forwarding and returning destination `crowdstrike`, plus audit tests for refreshed event strings, `BORDER0_API`, `PAM_CONNECTOR`, and `PAM_SERVICE_ACCOUNT` through existing interfaces.
- [x] 5.3 Add authorizeDevice 400/402 and approveUser 402 regressions verifying sanitized failure status/message handling without leaking unrelated fields or altering existing confirmation behavior.

## 6. Coverage, Documentation, and Verification

- [x] 6.1 Add snapshot-wide coverage completeness tests that fail for unmapped operations or missing registrations, assert the three new canonical grants/confirmations/hints, and guard the original 90 mapping identities and statuses against regressions.
- [x] 6.2 Update operator documentation with the three Alpha tools, pagination/body examples, exact and group grants, upstream OAuth scopes versus unchanged startup requirements, API-only semantics, one-time-secret warnings, configured-target-only deletion, and wildcard selector expansion; state that no new resources or prompts are added.
- [x] 6.3 Run `make verify` and review generated JSON/Markdown/diff coverage reports for 93 implemented operations, zero gaps/exclusions, and unchanged original mappings; do not re-fetch or overwrite the user's refreshed snapshot.
- [x] 6.4 Run `go build ./...`, `go test -race ./...`, and `git diff --check`; verify existing stdio/HTTP tests pass and all lifecycle network tests use mocks rather than live mutations.
