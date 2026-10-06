## 1. Cached Aperture Contract

- [x] 1.1 Verify the downloaded `tools/aperture/openapi.json` and metadata checksum, source, versions, and five-operation inventory; add an offline contract test that detects metadata or mapping drift.
- [x] 1.2 Add an explicit `aperture-openapi-refresh` command/Make target that validates a temporary download before replacing the snapshot and metadata; test failed downloads and invalid candidates preserve the cache. Keep existing Tailscale refresh behavior unchanged.

## 2. Aperture Client and Configuration

- [x] 2.1 Add `--aperture-url` / `APERTURE_URL` with default `http://ai/aperture`, base-path-preserving normalization, and pre-serving URL validation; test invalid schemes, userinfo, query, fragment, and trailing slash cases.
- [x] 2.2 Implement an injectable `internal/aperture` client with operation-specific requests, 30-second timeout, 16 MiB response limit, cancellation, no redirects or environment proxy, normal TLS verification, and no forwarded credentials or identity headers.
- [x] 2.3 Implement structured JSON/HuJSON result handling and sanitized RFC 9457/status errors; test 403, 412, 422, 5xx, malformed/truncated/oversized bodies, cancellation, timeout, redirect rejection, and secret-echoing diagnostics.

## 3. Aperture Configuration Tools

- [x] 3.1 Implement `aperture_get_config` with upstream-redacted config and exact ETag output, and `aperture_validate_config` with typed nonblank config input and sanitized structured validation output; test requests, input rejection, and absence of write side effects.
- [x] 3.2 Implement `aperture_set_config` with full replacement semantics, `confirm: aperture_set_config`, and one concrete `if_match` ETag; test rejection of missing/invalid inputs, wildcard/list validators, and confirmation mismatch before backend access.
- [x] 3.3 Test successful conditional replacement, redacted output/new ETag, 412 conflict without retry, uncertain write outcomes without retry, and tool descriptions warning about destructive replacement and redacted provider keys.

## 4. Aperture Pricing Tools

- [x] 4.1 Implement `aperture_get_pricing` and `aperture_get_model_pricing` with typed inputs, optional conditional headers, structured pricing output, and bodyless 304 handling with validator fallback.
- [x] 4.2 Test slash-separated exact model identifiers, reserved-character encoding, traversal rejection, empty model results, HuJSON normalization, decimal string/unit preservation, and bounded full-catalog errors without invented pagination or filtering.

## 5. Independent Catalogs and Grants

- [x] 5.1 Construct a separate Aperture MCP server with input validation, sanitized recovery, caller-filtered discovery, handler-level checks, and trusted `aperture-config` / `aperture-pricing` metadata; validate five-operation registration parity against the cached contract.
- [x] 5.2 Add tests for exact permissions, both Aperture groups and read-only group selectors, `read:*`, `*`, unknown selectors, missing/malformed grants, and unchanged Tailscale selectors; assert denied calls make zero backend requests and validation is read-only while replacement is not.
- [x] 5.3 Extend offline `--list-groups` to include both catalogs for HTTP and only Tailscale for stdio, preserving JSON entry shape and deterministic ordering; verify no credentials, tsnet startup, schema download, or upstream access is required.
- [x] 5.4 Verify separate catalog construction cannot alter the existing Tailscale surface or authorization, including concurrent construction and per-request grant changes within sessions.

## 6. Shared HTTP Routing and Tailscale Preservation

- [x] 6.1 Expose the existing Tailscale HTTP surface at preferred `/tailscale/mcp`, retaining `/mcp` as a backward-compatible alias to the same handler, server, catalog, and session state without redirects; mount the independent Aperture handler at `/aperture/mcp` on each enabled listener.
- [x] 6.2 Connect the Aperture client through the running tsnet node's dialer, minimally extending the tailnet abstraction/test fakes; verify no host Tailscale daemon or live Aperture startup probe is needed and unavailable Aperture does not block Tailscale serving.
- [x] 6.3 Preserve common Host/Origin validation, body limits, request grants, TLS behavior, readiness cancellation, listener acquisition, and shutdown; report service URLs on shared ports. Verify identical grants and protections for both Tailscale aliases on both listener types.
- [x] 6.4 Add protocol tests on tailnet and opt-in loopback for service-specific discovery, unavailable cross-service tools/resources/prompts, cross-service session isolation, direct-call denial, local-versus-tailnet grant separation, and transport protections.
- [x] 6.5 Update existing Tailscale startup/transport fixtures for the new path and verify unchanged core, generated, curated, resource, and prompt registrations, Admin API client behavior, exact permissions, mutation safeguards, and deprecated Tailscale-only stdio without Aperture initialization.
- [x] 6.6 Extend lifecycle tests for simultaneous streams on both routes and enabled loopback, preserving the existing shared shutdown deadline and failure exit status.
- [x] 6.7 Verify direct `/mcp` handling without redirects, the same Tailscale handler/server/session state across both aliases, per-request grants, identical protections on tailnet and enabled loopback, and unchanged Aperture isolation; record results after running.

## 7. Operator Documentation and Verification

- [x] 7.1 Update README, usage guidance, deployment/client examples, and endpoint references for preferred `/tailscale/mcp` and backward-compatible `/mcp` sharing the same Tailscale handler/server/session state without redirects, with identical grants and protections on both listener types; keep `/aperture/mcp` separate on the same port. Document Tailscale-only stdio, unchanged startup credentials, `APERTURE_URL`, and URL changes only for rollback clients using a path unsupported by the older binary.
- [x] 7.2 Document all five Aperture tools, inputs, exact permissions, read/write annotations, group selectors, wildcard permission expansion, MCP-node upstream identity, admin versus `read_pricing` requirements, ETag/confirmation workflow, and redacted-config precautions. State that no Aperture resources or prompts are added.
- [x] 7.3 Document offline snapshot use and explicit tailnet-only refresh, including checksum/provenance and reviewed operation-coverage updates; ensure routine build/test/coverage targets never fetch the live schema.
- [x] 7.4 Run `go test ./...`, `go test -race ./...`, `make coverage`, and `openspec validate add-aperture-mcp --strict`, with unchanged Tailscale coverage and complete Aperture cached-schema coverage.
- [x] 7.5 Record whether an optional tailnet smoke test of non-mutating tools was performed, including upstream role prerequisites or why it was skipped; do not perform a live configuration replacement without explicit operator approval.
- [x] 7.6 Rerun automated verification after the alias changes and update `verification.md`; do not treat prior results as verification of the new requirement.
