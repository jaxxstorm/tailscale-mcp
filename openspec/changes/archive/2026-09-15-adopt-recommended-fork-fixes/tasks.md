## 1. Build and Safe Integration Foundations

- [x] 1.1 Record the upstream registration/coverage baseline and reproduce the reported build failure; inspect only relevant fork source patches and record attribution without importing runtime artifacts or fork history wholesale.
- [x] 1.2 Align gVisor with the pinned Tailscale module, minimize dependency churn, and verify `go build ./...` succeeds with the declared Go toolchain.
- [x] 1.3 Derive verification and release Go versions from `go.mod`; add pull-request build/test/coverage checks and gate release publishing on successful verification.
- [x] 1.4 Ignore runtime tsnet directories and check tracked files, container build context, and release packaging exclude fork state, keys, certificates, and logs.

## 2. Shared Tool and Resource Authorization

- [x] 2.1 Replace string context keys and first-entry capability handling with typed context and unioned `tailcfg.UnmarshalCapJSON` parsing; test multiple entries, duplicates, missing grants, malformed entries, and spoofed headers.
- [x] 2.2 Implement exact resource matching plus explicit non-empty descendant `/*` matching; test empty selectors, collection/entity boundaries, lookalike prefixes, global `*`, and separation from tool permissions.
- [x] 2.3 Preserve explicit handler checks and fix successful-text permission denials; test denied tool/resource requests make zero Admin API calls.
- [x] 2.4 Validate core `get_device_info` inputs and enable sanitized tool/resource panic recovery; test invalid argument shapes and successful requests after a recovered panic.

## 3. Local Transport Authorization

- [x] 3.1 Add strict local-grant JSON configuration and the independent local HTTP enable/port flags and environment variables; test malformed/unknown fields, empty grants, invalid ports, defaults, and conflicting options.
- [x] 3.2 Inject local capabilities into stdio without tsnet startup or advertised-tag requirements; exercise actual stdio list/call and resource denial paths with permitted and absent grants.
- [x] 3.3 Enable loopback only with explicit HTTP opt-in and non-empty local grants, bind only `127.0.0.1`, and test grants alone do not open a listener or leak into tailnet authorization.

## 4. Tailnet TLS and HTTP Lifecycle

- [x] 4.1 Add optional Tailscale-backed TLS without a background readiness wait, independent tailnet/local port resolution, and full endpoint URL logging; test explicit ports, defaults, certificate/listener failures, and no plaintext fallback.
- [x] 4.2 Implement strict origin tuple validation without trusting forwarded headers; test suffix attacks, scheme mismatch, default ports, malformed/multiple/null origins, and absent Origin.
- [x] 4.3 Exercise loopback Host/DNS-rebinding protection through the production MCP middleware stack, including matching malicious Origin/Host and requests without Origin.
- [x] 4.4 Add header/idle timeouts, 4 MiB POST limits, and a 30-second body-read deadline compatible with MCP streaming; test chunked and sized overflow, slow bodies, grantless peers, representative ACL payloads, and streams surviving body deadline cleanup.
- [x] 4.5 Refactor serving to return errors after cleanup, acquire all listeners before accepting work, and close acquired resources on bind failures; test failure of the second listener.
- [x] 4.6 Coordinate concurrent listener shutdown, context cancellation, bounded drain, forced closure, and tsnet cleanup; test open SSE plus local traffic, both signals, drain timeout diagnostics, and nonzero exit on unexpected serving errors.
- [x] 4.7 Validate tailnet Host against ready-node DNS names/IPs and port, and cancel readiness/listener acquisition safely; test malicious matching Host/Origin, missing Origin, blocked readiness, partial bindings, and initialization/cleanup ordering.

## 5. Startup Credentials and Federation

- [x] 5.1 Add exclusive inline/file federated assertion sources and a rereading file callback; test whitespace, atomic replacement, missing/unreadable/empty files, ambiguous sources, and existing inline/OAuth/bearer behavior.
- [x] 5.2 Propagate tsnet assertion snapshot errors and apply the 30-second startup validation deadline; test failure before serving and preserved low-risk validation scope behavior.
- [x] 5.3 Test both typed and generic Admin API clients against a mock federation/token endpoint, demonstrating refreshed assertions after access-token expiry and no fallback to stale assertions.
- [x] 5.4 Handle `--version` before credential/tailnet validation and network initialization; add an offline CLI regression test.

## 6. Catalog and Registration Across API Domains

- [x] 6.1 Implement server-owned catalog metadata and shared exact/read/group selector evaluation; test OR semantics, unknown selectors, duplicate/incomplete metadata, and independent server instances.
- [x] 6.2 Register and verify metadata for core/device tools, generated device endpoints, routes, posture attributes, and curated device/bulk workflows while retaining all existing names and schemas.
- [x] 6.3 Register and verify metadata for policy/ACL, DNS, keys, invites, users, and tailnet settings tools, including composed/read-like operations and mutating operations with misleading names.
- [x] 6.4 Register and verify metadata for logging and special network-flow-log handling, posture, services, webhooks, remaining generated domains, and optional local diagnostics; retain the local CLI opt-in boundary.
- [x] 6.5 Add exact registration/catalog set equality and annotation parity tests with local CLI on and off; verify existing curated wrappers remain present and unchanged.
- [x] 6.6 Add deterministic credential-free `--list-groups` output for the configured tool surface and test that it performs no network initialization.

## 7. Grant-Filtered MCP Discovery and Calls

- [x] 7.1 Install per-request SDK tool filtering using the same catalog/evaluator as handler checks; do not add profiles or change resource discovery.
- [x] 7.2 Test actual MCP initialization/list/call through HTTP and stdio for exact, global, read-only, group, and read-only-group grants; assert direct calls to denied tools produce zero API/CLI side effects.
- [x] 7.3 Test different callers and reused session IDs for grant isolation, plus concurrently constructed server instances under the race detector.
- [x] 7.4 Re-run mutation-confirmation, ETag, pagination/filtering, network-flow-log continuation, bulk partial-failure, and sanitized upstream-error tests to demonstrate endpoint behavior is unchanged.

## 8. Documentation and Final Verification

- [x] 8.1 Update usage/CLI examples for explicit stdio grants, separate loopback opt-in, independent ports, HTTPS prerequisites, certificate transparency, body limits, and shared-host trust risks.
- [x] 8.2 Document resource-prefix migration, selector OR semantics and future expansion, sensitive read access, stable tool/group names, unchanged curated tools, and separate resource permissions.
- [x] 8.3 Document token-file atomic rotation/protection, Admin API versus tsnet refresh scope, startup timeouts, shutdown uncertainty for interrupted mutations, and configuration rollback considerations.
- [x] 8.4 Run `go build ./...`, `go test ./...`, `go test -race ./...`, and `make verify`; compare regenerated coverage with the baseline and investigate any mapping, schema, confirmation, or curated-registration change.
- [x] 8.5 Validate release verification wiring and inspect package contents and final diffs for unintended dependencies, excluded features, runtime artifacts, and missing source attribution.
- [x] 8.6 Perform isolated live-tailnet HTTPS/WhoIs/federation smoke tests with fresh operator-owned state when credentials are available; otherwise explicitly record these as unverified without using fork-bundled credentials.
- [x] 8.7 Run `openspec validate adopt-recommended-fork-fixes --strict` and verify implementation against every changed requirement before considering the change complete.
