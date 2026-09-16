# Implementation Verification

## Baseline and Attribution

- Upstream baseline: `c31bacc01e9aa181791f2c90d8ea8847230a911a`.
- Reviewed fork: `jstevewhite/tailscale-mcp` through `481c08280c1a005731ad9821d8c8b71ebc1da2d8`.
- Canonical checked-in coverage: 90 operations implemented, zero gaps. Existing registration tests and upstream Git versions are the comparison baseline for tool names and schemas; retain curated wrappers.
- Baseline `go build ./...` failed with conflicting gVisor package declarations: `stack` / `bridge` and `refs` / `refs_template` at revision `ddf37c50b366`.
- Build correction is based on fork commit `141c42a28e6f32d5f716cdc786b7d13fd0599153`: use the gVisor revision pinned by Tailscale v1.100.0, `573d5e7127a8`.
- Relevant fork source was reviewed through the GitHub API. No fork history, runtime state, certificates, keys, or logs were imported.

## Verification Results

- After changing the gVisor pin and running `go mod download gvisor.dev/gvisor`, `go build ./...` progressed past the conflicting package errors but failed in `runtime/cgo` because the local Xcode license has not been accepted.
- On resumption, `go build ./...` passed with the corrected gVisor pin. The native toolchain blocker is resolved; the assistant did not accept the license or change system configuration.
- Final `go build ./...`, `go test ./...`, and `go test -race ./...` passed with all implementation and startup integration tests.
- `make verify` passed: 90 total operations, 90 implemented, zero gaps/exclusions. `git diff --exit-code -- coverage` reported no changes from the baseline.
- `go mod tidy -diff` is empty. Module changes are the corrected gVisor revision, promotion of the already-pinned OAuth library to a direct dependency, and removal of stale unused requirements/checksums; no dependency versions were upgraded.
- `git diff --check` passed. Workflow `actionlint`, release-gate checks, documentation JSON examples, and local documentation links were checked successfully.
- Final read-only review found no remaining concrete in-scope findings after the approved startup/Host hardening and strict capability shape fixes.
- `openspec validate adopt-recommended-fork-fixes --strict` passed after artifact updates. All 39 implementation tasks are complete, including the explicit documentation of unavailable live verification.

## Regression Coverage

- `grants_test.go`: typed capability snapshots, union of all matching rules, strict shape rejection including null fields/elements, duplicate and unknown keys, spoofed identity headers, exact resource boundaries, and tool/resource permission separation.
- `catalog_test.go`, `internal/toolmeta/*_test.go`, and `internal/readapi/metadata_test.go`: selector semantics, all registration layers, catalog/annotation/name parity, curated schema retention, optional local CLI, independent concurrent servers, reused-session grants, denial before API/CLI side effects, core input validation, and sanitized recovery.
- `credential_refresh_test.go`: typed and generic client token exchanges, actual access-token expiry and assertion rotation, cached-token reuse, file failures without stale fallback, request deadlines, OAuth/inline/bearer regressions, and reflected-secret error redaction.
- `localgrants_helpers_test.go` and `transport_helpers_test.go`: strict local configuration, explicit opt-in, independent ports, origin and Host validation, actual stdio context propagation, body bounds, slow TCP reads, stream deadline clearing, and concurrent bounded shutdown.
- `startup_integration_test.go`: real entry-point subprocess tests for offline CLI and stdio, Kong flags/environment precedence, configured HTTP/stdio initialization/list/call selector matrices, zero denied API/CLI effects, TLS handshake behavior, and SIGINT/SIGTERM/failing-listener process exit behavior.
- `tailnet_startup_test.go`: production tailnet serving with mocked node status/WhoIs, canonical Host validation, malicious Host/Origin denial, TLS certificate success/failure, cancellation before/during listener acquisition, partial-bind cleanup, blocked readiness, and initialization/close ordering.
- Existing mutation confirmation, ETag, network-flow-log continuation, pagination/filtering, partial-failure, annotation, and upstream-error suites passed unchanged in behavior.

## Packaging and Attribution

- `docs/integration.md` attributes the selected improvements to `jstevewhite/tailscale-mcp` and identifies the relevant source commits; profiles, wrapper removal, and runtime artifacts are explicitly excluded.
- Tracked-file checks found no fork state/key/certificate/log files. Docker build context was exported and inspected: only Go build inputs were included.
- GoReleaser 2.17.0 built a non-publishing darwin/arm64 snapshot using a temporary copy of the release config restricted to that platform and a temporary dist directory. The before/publish/announce/homebrew/sign/sbom steps were skipped; the module graph had already been tidied and verified.
- The actual archive contains exactly `tailscale-mcp`, `README.md`, `docs/usage.md`, and `docs/integration.md`. The binary was confirmed as Mach-O arm64. No repository artifacts were published, committed, or pushed.
- Full cross-platform release builds were not run. GoReleaser reports existing deprecated archive/brew configuration fields; the snapshot succeeds, but `goreleaser check` exits nonzero on those deprecation notices. Migration of those unrelated fields is not included.

## Live Verification and Limits

- Live-tailnet HTTPS issuance/renewal, real WhoIs capability delivery, and production federation have not been verified. No dedicated live test tailnet/credentials were supplied for this change; tests use isolated local mocks, synthetic tokens, and test certificates, never fork-bundled credentials or state. This records the explicit fallback allowed by task 8.6, not a claim of live success.
- SDK `tsnet.Start()` has no cancellation API and must not race `Close()`. Cancellation during initialization is handled when Start returns; readiness and listener acquisition after initialization are cancellable. The 30-second Admin validation deadline is not an overall startup deadline.
- Resource grants now require explicit `/*` for descendants, loopback requires separate opt-in, and tailnet aliases outside canonical node names/IPs are rejected. These migrations are documented in the usage guide and design.
