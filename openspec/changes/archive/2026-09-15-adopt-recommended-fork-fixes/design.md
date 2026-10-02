## Context

Upstream `c31bacc` and fork `jstevewhite/tailscale-mcp` through `481c082` were compared read-only. The fork fixes first-entry-only capabilities, unsafe resource/origin prefix matching, missing local authorization, and static federated assertions. Its implementation also contains tracked runtime credentials, global catalog ownership, incomplete shutdown, and optional features outside this change. Static review is not evidence of a passing build or live tailnet integration.

The server combines core handlers, generated/table-driven Admin API registration, and curated workflows. Existing endpoint names, `tailscale://` URIs, canonical coverage records, pagination, network-flow-log cursors, structured API errors, and per-item partial failures must remain intact. All existing API domains are affected only through these shared mechanisms; no endpoints or prompts are added.

## Goals / Non-Goals

**Goals:**
- Restore reproducible builds and working least-privilege local access.
- Make grant evaluation consistent across discovery and execution without weakening mutation confirmations.
- Support HTTPS clients and externally refreshed OIDC assertions.
- Bound HTTP resource consumption and stop both listeners reliably.
- Preserve attribution and existing public tool identities while importing only reviewed source.

**Non-Goals:**
- Named profiles, URL-selected tool sets, YAML profile configuration, or wrapper deletion.
- Automatic OIDC token acquisition, a new identity provider, or tsnet reauthentication refresh guarantees.
- Authenticated multi-user loopback service, Unix socket transport, new API coverage, or unrelated curated-handler cleanup.
- Importing fork Git history wholesale, state, keys, certificates, logs, or planning documents.

## Decisions

### Selective source integration and reproducible verification

Use focused ports from the reviewed fork, retaining attribution and source commit references in integration documentation/commit descriptions. Inspect each patch's file list; do not merge the fork branch. Start with `141c42a`'s gVisor correction after reproducing the build issue and confirming the version against the pinned Tailscale module. Use `actions/setup-go` with `go-version-file: go.mod` in verification and release workflows. Run tests and coverage validation before release; avoid unrelated dependency churn. Ignore runtime tsnet directories and verify no such artifacts are tracked or packaged by this change. Blanket cherry-picking is rejected because useful commits can contain unrelated runtime files.

### One authorization evaluator with server-owned metadata

Parse `tailcfg.PeerCapMap` once per tailnet request with `tailcfg.UnmarshalCapJSON`, union all entries for `jaxxstorm.com/cap/mcp`, and store capabilities and identity using private typed context keys. Malformed capability data rejects the request; missing grants authorize no operations. Local grants use the same capability shape and evaluator but are injected only by the local transport configuration, never from client headers.

Create a catalog owned by each MCP server and pass its access-check/filter closures to core, generated, special network-flow-log, and curated registrations. Keep it immutable after registration. Record exact tool name, stable group, and read-only classification from the same trusted registration metadata that supplies MCP annotations. Infer generated groups systematically from endpoint metadata, with explicit overrides for exceptions and composed tools; never infer read-only safety from a tool's name. Validate duplicate names, missing groups, and catalog/registration/annotation parity at startup or construction. No process-global pointer is needed.

Selectors in `tools` are ORed: exact name, `*`, `read:*`, `group:<name>`, and `group:<name>:read`. Unsupported or unknown selectors match nothing; do not interpret them as arbitrary globs. Exact names stay compatible. All selectors operate on registered tools; optional local CLI tools remain absent unless separately enabled. Document that read-only can expose sensitive data and that selector permissions expand when matching tools are added. `--list-groups` prints deterministic metadata for the configured tool surface without contacting Tailscale.

Install the MCP SDK filter for per-request `tools/list` and `tools/call`, and retain explicit handler checks as defense in depth. Use the same evaluator and metadata in both places. Check the pinned SDK's behavior through real protocol dispatch tests, not just helper tests; a hidden tool must not execute by name. Resources remain separately authorized; tool selectors confer no resource access and resource discovery filtering is not introduced.

### Explicit resource hierarchy rather than implicit prefixes

Match resources exactly, allow `*` globally, and interpret only trailing `/*` as a non-empty descendant beneath the preceding slash. For example, `tailscale://devices/*` permits `tailscale://devices/123`, but not `tailscale://devices`, `tailscale://devices/`, or `tailscale://devices-other/123`. Empty selectors never match. Compare the URI representation accepted by registered resource handlers without introducing decoding or normalization that broadens grants. Retaining implicit prefixes is rejected because it preserves overgranting.

### Local transports are explicit trust choices

Add `--local-grants` / `TS_MCP_LOCAL_GRANTS` for a single JSON capability entry. Validate shape strictly; malformed configuration fails startup. Unset or empty configuration grants nothing. Stdio injects the configured capabilities through the SDK context hook, does not start tsnet, and does not require advertised tags. It remains deprecated and still validates Admin API credentials before serving.

Unlike the fork, add a separate `--local-http` / `TS_MCP_LOCAL_HTTP` boolean, default false. In HTTP mode it requires an explicit non-empty local grant and binds only `127.0.0.1` on `--local-port` / `TS_MCP_LOCAL_PORT` (default 8080). Merely configuring stdio grants must not expose an HTTP endpoint. Loopback stays plain HTTP and trusts every process able to connect; no same-user authentication is claimed. Keep SDK Host validation and add full-stack DNS-rebinding regression tests. Reject invalid ports and contradictory local listener configuration before opening listeners.

### Tailnet TLS and strict browser origins

Add `--tls` / `TS_TLS`, default the tailnet port to 443 with TLS and 8080 otherwise, and honor an explicit valid `--port` / `TS_PORT`. Use a context-aware equivalent of `tsnet.ListenTLS`: await `Up(ctx)` before acquiring listeners, check MagicDNS and certificate-domain prerequisites, and wrap `tsnet.Listen` with `tls.NewListener` using `LocalClient.GetCertificate`. The pinned SDK's `ListenTLS` performs another `Up(context.Background())`, so calling it would make readiness uninterruptible. TLS failure must never fall back to HTTP. Log the scheme, ready node's MagicDNS name, port, and `/mcp`; do not change local port behavior. Certificates require tailnet HTTPS support and can publish the DNS name through certificate transparency.

If Origin is present, accept only a serialized HTTP(S) origin with no credentials, path, query, or fragment, matching the actual listener scheme, hostname, and effective port. Normalize hostname case and default ports, reject `null` and multiple origins, and do not trust forwarded headers to choose the scheme or identity. Requests without Origin remain supported for non-browser MCP clients. Independently validate tailnet Host against the ready node's full/short DNS name and Tailscale IPs at the configured port; arbitrary aliases and matching attacker-controlled Host/Origin pairs are rejected before identity lookup. Do not trust the CLI hostname as a substitute for the registered node identity.

### Refresh assertions without silently changing tsnet behavior

Add `idTokenFile` to federated credential JSON. Require one of inline `idToken` or `idTokenFile`, rejecting both to avoid ambiguous precedence. The Admin API federation callback rereads and trims the file for each assertion request; it does not reread for every API request when the SDK can reuse an access token. Missing, unreadable, or empty files produce errors without falling back to an old assertion or logging token bytes. External refreshers must use atomic replacement and restrictive permissions.

Configure tsnet from a startup snapshot and return file-read errors to startup rather than logging and continuing. Do not claim continuous tsnet assertion refresh. Keep credential validation on the existing low-risk read with a 30-second context deadline. The pinned Admin SDK caches identity assertions and uses background exchange contexts: wrap token acquisition so each access-token refresh constructs a fresh federation source, binds exchange I/O to the active request, and sanitizes exchange failures. Retain access-token caching and a cancellable refresh gate for concurrent callers; apply request-bound token exchange to OAuth too. Handle `--version` and `--list-groups` before mandatory tailnet/credential validation or network activity; otherwise preserve existing credential formats and startup scope requirements.

### Bounded transport and coordinated lifecycle

Use header and idle timeouts (10 and 120 seconds). Bound POST bodies to 4 MiB with `http.MaxBytesReader` before SDK dispatch and apply a 30-second body-read deadline, cleared when body consumption finishes so tool execution and SSE streams do not inherit it. Use listener/connection-aware mechanisms compatible with the pinned SDK; avoid a blanket write timeout that truncates legitimate streaming. Return an HTTP/MCP error for oversized or timed-out bodies without dispatching an operation. These limits apply even to peers without MCP grants.

Validate the core `device` argument rather than asserting its type; permission/input failures are MCP error results. Enable tool/resource panic recovery with sanitized client errors and internal diagnostics. Never log credential material or expose stack traces in client responses. Existing structured upstream error mapping, pagination, filters, and partial-success payloads remain unchanged.

Factor serving into a function returning an error so cleanup completes before process exit. Bind configured listeners before launching serving goroutines; close acquired resources if a later bind fails. On SIGINT/SIGTERM, stop acceptance on both HTTP listeners concurrently, cancel long-lived stream/request contexts, and drain within one ten-second budget. Report drain errors, force-close residual HTTP connections, and close tsnet after HTTP cleanup. Expected signal shutdown exits successfully; unexpected serving errors remain nonzero after cleanup. Simulated listeners and open SSE streams provide deterministic lifecycle tests without live tailnet credentials.

Initial `tsnet.Start()` has no context parameter and its documentation prohibits concurrent `Close()`. Run it synchronously; on failure rely on SDK initialization cleanup, and after success own exactly one close. Cancellation during initialization is observed when it returns; readiness then uses the caller's context and all listener acquisitions check cancellation before and after binding. Do not claim that the 30-second Admin validation deadline bounds SDK initialization, or close a partially initialized server from a cancellation goroutine.

## Risks / Trade-offs

- Resource policy compatibility changes -> Publish exact-to-descendant migration examples and test boundary cases; never retain unsafe implicit prefixes as a compatibility fallback.
- Local processes inherit powerful server credentials through grants -> Separate HTTP opt-in, default denial, narrow examples, and explicit shared-host warnings.
- Wildcard/group permissions grow on upgrades -> Stable documented groups, catalog diff review, and recommend exact grants for tightly controlled deployments.
- Metadata mistakes affect authorization -> Single trusted source, exact parity tests, server-instance isolation tests, and race testing.
- HTTP body limits can reject unusually large ACL submissions -> Document the 4 MiB limit and test representative ACL bodies; revisit deliberately rather than leaving bodies unlimited.
- Cancellation can interrupt in-flight mutations -> Do not retry automatically or claim rollback; document ambiguous outcomes and preserve operation context in diagnostics.
- Live TLS and federation are environment-dependent -> Use mocks for CI, document isolated smoke tests with fresh state, and report live verification gaps explicitly.

## Migration Plan

1. Port and verify build/correctness foundations, then local transport/TLS/credentials, then metadata/filtering/selectors. Keep source attribution per logical port.
2. Before deployment, replace implicit resource prefixes with exact URIs and/or explicit `/*` grants. Exact tool grants and all curated names remain valid.
3. Operators needing loopback configure both `--local-http` and narrow `--local-grants`; stdio requires only the local grant. Explain the disabled-by-default listener in release notes.
4. Opt into TLS and token files independently. Use fresh or operator-owned state only, never fork-bundled state.
5. Run full verification, compare coverage metadata against the pre-change baseline, and review catalog changes with local CLI enabled and disabled.
6. Rollback requires removing unsupported flags/selectors and restoring policies compatible with the older binary. Prefer a forward fix for resource authorization because reverting reintroduces prefix overgranting. No persisted-state migration is introduced.

## Open Questions

No blocking product decisions remain. Implementation must verify the pinned SDK's body-read and stream-cancellation integration and record any unavailable live-tailnet validation. If SDK behavior prevents the stated bounds or denial semantics, revise the design explicitly rather than weakening them silently.
