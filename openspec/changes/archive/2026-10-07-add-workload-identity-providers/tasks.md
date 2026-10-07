## 1. Credential Configuration and Acquisition Boundary

- [x] 1.1 Extend federated credential JSON with explicit `provider`, Kubernetes-only `tokenFile`, and AWS-only `region`; require `clientId` and `audience` in provider mode and exactly one assertion source. Test type inference, missing/blank/wrong-type settings, mixed sources, unsupported providers, and preservation of legacy OAuth/bearer/inline/file forms.
- [x] 1.2 Add a small context-aware provider acquisition boundary with injected HTTP/AWS dependencies and clock for tests, without automatic detection, a plugin framework, global transport mutation, or eager provider I/O during parsing.
- [x] 1.3 Implement bounded provider output and JWT sanity validation (compact format, expiration, string/array audience), sanitized errors, and cancellation propagation. Test malformed, empty, expired, wrong-audience, oversized, and secret-bearing failures without making local claims authoritative for MCP authorization.

## 2. Kubernetes Projected Tokens

- [x] 2.1 Implement Kubernetes acquisition from the configurable projected-token path, default `/var/run/secrets/tailscale/token`, reopening the current symlink target, accepting regular files only, trimming contents, enforcing the size bound, and checking cancellation before/after local I/O.
- [x] 2.2 Test kubelet-style symlink rotation and missing, unreadable, empty, non-regular, oversized, and invalid files. Verify no fallback to the default API token, previous assertion, cloud metadata, or Kubernetes API issuance occurs.

## 3. AWS STS Identity Tokens

- [x] 3.1 Implement lazy AWS SDK config/credential loading with explicit-region precedence, SDK region fallback, and bounded EC2 IMDS discovery only when needed. Reuse pinned SDK versions, promote directly imported modules as needed, and test configured-region behavior without live metadata.
- [x] 3.2 Implement regional `GetWebIdentityToken` with the single audience, ES384 algorithm, and 300-second duration, using bounded context-aware transport/retries and validated output. Test exact request parameters, empty/invalid responses, credential/region/permission failures, cancellation, redirects, and secret-safe errors with fake SDK boundaries.

## 4. GCP Metadata Identity Tokens

- [x] 4.1 Implement fixed-endpoint GCP acquisition with encoded audience, `format=full`, metadata request/response headers, HTTP 200 enforcement, no redirects/proxies, and bounded validated JWT output.
- [x] 4.2 Test request construction, missing metadata headers, unsuccessful status, invalid/oversized bodies, timeout/cancellation, ignored endpoint-override environment variables, and no ADC/key-file/cross-provider fallback using fake transports.

## 5. Tailscale Token Exchange and Refresh

- [x] 5.1 Thread request context into assertion acquisition and the SDK federation callback while retaining the existing refresh lock, fresh SDK source per refresh, cached access-token reuse, and context-bound `/api/v2/oauth/token-exchange` requests.
- [x] 5.2 Extend typed and generic Admin API client tests for provider reacquisition on access-token expiry, no reacquisition while a token remains valid, cancellation during acquisition/exchange/lock contention, rotated assertions, no stale fallback, and no protected mutation dispatch or replay after acquisition failure.
- [x] 5.3 Verify the startup tailnet-settings read shares its existing 30-second deadline with provider acquisition and token exchange, and that exchange/validation failures remain sanitized. Preserve existing file-refresh and OAuth credential regression tests.

## 6. tsnet Enrollment and Service Modes

- [x] 6.1 Thread startup context into pre-tsnet assertion acquisition with its 30-second budget, set only `ClientID` and the supplied `IDToken`, and stop forwarding credential `audience` as a simultaneous tsnet selector. Test provider and legacy inline/file forms, cancellation before `Start()`, and sanitized acquisition failures.
- [x] 6.2 Reject conflicting ambient `TS_AUDIENCE`, `TS_AUTHKEY`, `TS_AUTH_KEY`, and `TS_CLIENT_SECRET` for federated HTTP before acquisition/enrollment, naming variables without values and without globally unsetting them. Test unrelated/overridden client-ID and ID-token environment behavior and stdio remaining unaffected by tsnet-only conflicts.
- [x] 6.3 Add startup tests for Tailscale-only and combined HTTP, Aperture-only enrollment without Admin API clients/read scopes/tailnet name, and Tailscale-only stdio without tags or a separate enrollment snapshot. Preserve service-toggle errors, listener/state isolation, readiness cancellation, and cleanup behavior.
- [x] 6.4 Verify `--version` and every enabled-service `--list-groups` combination remain offline with unusable provider configurations and ambient cloud variables. Verify provider credentials do not change registrations, incoming grant checks, exact permissions, resource URIs, or mutation confirmations.

## 7. Documentation and Deployment Examples

- [x] 7.1 Document credential JSON, supported providers, explicit selection/no fallback, Kubernetes projection path/audience/rotation/permissions, publicly reachable issuer/JWKS, and a token-volume manifest without `subPath` or unnecessary TokenRequest RBAC.
- [x] 7.2 Document AWS workload-role and credential-chain prerequisites, region selection, least-privilege `sts:GetWebIdentityToken` audience/duration policy, and GCP attached-service-account metadata setup. Explicitly defer Azure, GitHub-specific acquisition, automatic detection, and unsupported identity mechanisms.
- [x] 7.3 Update startup/federation guidance for independent service modes, provider versus Admin API access-token refresh, tsnet snapshot/cancellation limitations, sanitized diagnostics, ambient tsnet conflicts, and rollback to legacy credentials. State that no MCP tools/resources/prompts or grant names are added; include any new guide/example files in release archive inputs and verify documentation links.

## 8. Final Verification

- [x] 8.1 Run `go test ./...`, `go test -race ./...`, `make coverage`, and `openspec validate add-workload-identity-providers --strict`; resolve failures and record results, confirming unchanged Tailscale and Aperture operation mappings.
- [x] 8.2 Record which optional Kubernetes/AWS/GCP live smoke tests were run or skipped and their prerequisites. Do not acquire live cloud credentials, enroll nodes, print tokens, or invoke MCP mutations as part of automated verification; obtain explicit operator authorization before live authentication tests.
