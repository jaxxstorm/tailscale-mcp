## Context

`main.go` currently accepts OAuth, bearer, and federated JSON credentials. Federation requires `clientId` and one of `idToken` or `idTokenFile`. The custom Admin API transport caches access tokens, creates a fresh SDK federation source on refresh, rereads assertion files, rebinds exchange HTTP to the caller context, and sanitizes exchange failures. tsnet receives a startup assertion snapshot.

The pinned modules are `tailscale.com v1.104.0` and `tailscale.com/client/tailscale/v2 v2.11.0`. The former's `wif.ObtainProviderToken` supports automatic GitHub/AWS/GCP discovery, but exposes no explicit-provider function, no Kubernetes projected-token source, and no implemented Azure source. AWS acquisition uses the current STS `GetWebIdentityToken` API, not a presigned GetCallerIdentity request. The Admin SDK accepts `IDTokenFunc func() (string, error)` but has no provider acquisition or context parameter. tsnet has `ClientID`, `IDToken`, and `Audience`, but no per-server assertion callback, and rejects simultaneous ID token and audience.

Service toggles must survive this change: Tailscale MCP defaults on, Aperture defaults off, Aperture-only HTTP skips Admin API initialization/validation, and stdio is Tailscale-only. Federation must not grant incoming MCP permissions or forward identity tokens to Aperture.

## Goals / Non-Goals

**Goals:**
- Provide deterministic, explicit Kubernetes, AWS, and GCP identity sources without long-lived Tailscale client secrets.
- Refresh provider assertions when Admin API access tokens need renewal and acquire an assertion before tsnet startup.
- Preserve existing credential forms, fail-closed grants, service selection, and offline informational commands.
- Bound provider I/O, sanitize failures, and provide deployable least-privilege examples and offline tests.

**Non-Goals:**
- Azure or GitHub-specific acquisition, automatic cross-provider detection, interactive login, or an external credential-plugin framework.
- Kubernetes TokenRequest calls or writing/rotating projected tokens; kubelet owns issuance and rotation.
- Arbitrary OIDC issuer authentication, Google ADC impersonation, cloud resource provisioning, or runtime trust-policy creation.
- Continuous tsnet assertion refresh or overriding the SDK's non-cancellable `Start()` behavior.
- New MCP tools/resources/prompts, grant names, or changes to read/write operation safeguards.

## Decisions

### Extend the existing JSON credential with explicit sources

Keep `TAILSCALE_OAUTH_TOKEN` / `--credential` as the single configuration entry point. Add these flat JSON fields to the federated form:

| Field | Meaning |
| --- | --- |
| `provider` | Exactly `kubernetes`, `aws`, or `gcp`; no auto-detection default |
| `audience` | Required, nonblank target audience for provider mode; use the exact value shown in the Tailscale trust credential |
| `tokenFile` | Kubernetes-only projected-token path; default `/var/run/secrets/tailscale/token` |
| `region` | Optional AWS-only region; otherwise use SDK region configuration, then EC2 IMDS region discovery |

Require `clientId` and exactly one assertion source: inline `idToken`, legacy `idTokenFile`, or nonempty `provider`. A provider may not coexist with either legacy assertion source. Reject unknown providers, wrong JSON field types, provider fields on OAuth/bearer credentials, `tokenFile` outside Kubernetes, and `region` outside AWS. Reject explicitly blank `tokenFile`/`region` rather than silently interpreting them as defaults; absence selects defaults. Type inference without explicit `type` recognizes a provider plus `clientId` as federation. Audience-only credentials remain invalid because automatic detection is not added.

Examples:

```json
{"type":"federated","clientId":"<tailscale-client-id>","provider":"kubernetes","audience":"<tailscale-audience>"}
{"type":"federated","clientId":"<tailscale-client-id>","provider":"aws","audience":"<tailscale-audience>","region":"us-east-1"}
{"type":"federated","clientId":"<tailscale-client-id>","provider":"gcp","audience":"<tailscale-audience>"}
```

Existing inline/file forms remain valid without an audience. If they contain `audience`, retain it as configuration metadata rather than forwarding it as tsnet's competing acquisition selector. Do not broadly tighten unrelated legacy JSON behavior in this change.

Alternative: audience-only auto-discovery could directly reuse `wif.ObtainProviderToken`, but its cross-cloud probes, GitHub precedence, and missing EKS-specific detection make identity selection less predictable. Explicit providers avoid accidental identity substitution and permit isolated tests. Do not call the auto-detection helper and then claim the configured provider is guaranteed.

### Small context-aware assertion acquisition boundary

Introduce a small internal provider module, not a registry/plugin system. Give acquisition a `context.Context` and immutable provider configuration; inject the HTTP transport, AWS config/STS boundary, and clock into tests. Keep the existing credential/exchange wrapper in control of access-token caching and sanitization.

Each provider acquisition has a maximum 30-second budget, shortened by any caller deadline. Cloud HTTP calls use request contexts, a maximum five-second per-request timeout, and finite SDK retries within that overall budget. Limit acquired token/file/metadata bodies to 1 MiB and reject overflow rather than truncate. Reopen files per acquisition, check cancellation before and after the read, and require a regular file after following Kubernetes projection symlinks; do not accept pipes/devices. Local regular-file I/O has no hard cancellation guarantee, so document that the token must be a local projected volume rather than a potentially blocking remote filesystem.

Trim provider output and validate compact JWT shape, decodable claims, future numeric `exp`, and matching `aud` (string or string array). Reject empty, malformed, expired, or wrong-audience tokens before exchange. These checks are sanity validation only: Tailscale remains responsible for signature, issuer, subject, and trust-claim verification. Never use decoded claims to authorize MCP callers. Do not cache provider JWTs in the application; only cache Tailscale access tokens as today.

### Kubernetes projected tokens, not API token issuance

Read `tokenFile` or the dedicated default path on every provider acquisition, following the current symlink target. Do not reuse the default Kubernetes API token implicitly: it commonly has the wrong audience. Provide a deployment example with a read-only projected `serviceAccountToken` volume, `audience` equal to the Tailscale trust audience, `expirationSeconds: 3600`, and the token mounted at `/var/run/secrets/tailscale/token`. Explain that `subPath` mounts do not receive projected-token rotation.

Kubelet performs issuance and rotation; the application needs no Kubernetes API client or TokenRequest RBAC. Configure the cluster's OIDC issuer as a custom Tailscale trust issuer with publicly accessible discovery/JWKS and restrict the subject to the intended namespace/service account. Private-only issuers are not supported by Tailscale merely because the workload is on a tailnet. EKS/GKE users can choose native projected-token federation or their cloud provider source, but the selected mode never silently changes.

### AWS regional STS identity issuance

Use the AWS SDK v2 packages already pinned transitively by Tailscale. Load config lazily on acquisition with the request context and the normal SDK credential chain, so EC2 instance profiles, ECS task roles, and EKS role-based credentials can refresh normally. Document the chain's environment/profile precedence and recommend workload roles, not static AWS keys. Do not automatically acquire a Kubernetes token unless the selected AWS credential chain itself requires a configured web-identity role exchange.

Resolve region from the explicit JSON field, otherwise SDK environment/shared configuration; if absent, attempt bounded EC2 IMDS region discovery. ECS/EKS deployments without IMDS must configure a region. Call regional STS `GetWebIdentityToken` with one audience, `SigningAlgorithm: ES384`, and `DurationSeconds: 300`. The caller role needs `sts:GetWebIdentityToken`, ideally constrained by `sts:IdentityTokenAudience` and `sts:DurationSeconds`. This is distinct from `AssumeRoleWithWebIdentity`, which can appear earlier in the AWS credential chain.

Use normal HTTPS validation and SDK endpoint resolution for AWS APIs. Do not add application-configurable token endpoints; fake transports/clients are test-only. Disable HTTP redirects and proxy use on the dedicated acquisition client so credential-bearing requests are not forwarded to a redirect target or an ambient proxy. Do not modify global HTTP configuration. Failure returns a sanitized provider/stage error with no SDK response body, AWS credentials, or JWT.

Alternative: duplicating AWS signing/metadata credential logic is unnecessary and unsafe. Reuse SDK config and STS directly instead of copying the Tailscale helper's auto-detection probes.

### GCP attached-service-account metadata identity

GET `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity` with URL-encoded `audience`, `format=full`, and `Metadata-Flavor: Google`. Require HTTP 200 and the expected metadata response header, bound the body, and apply the provider-JWT sanity checks. Disable redirects and environment proxies. The address is fixed in production; do not accept `GCE_METADATA_HOST` or caller-supplied metadata URLs. Inject transport only for offline tests.

Support attached service accounts where this endpoint exists, including appropriately configured GCE/GKE environments. Do not fall back to user ADC, a service-account key file, IAM impersonation, or another cloud if metadata acquisition fails. The attached identity and trust configuration must permit the intended audience and workload claims.

### Preserve refresh semantics and startup boundaries

Change assertion acquisition to accept context. On each Admin API access-token refresh, create a fresh SDK `IdentityFederation` source whose callback captures the initiating request context and invokes the selected assertion source. Keep the context-aware refresh lock, fresh SDK source, cached access-token reuse, context-bound token exchange, and sanitized errors already in place. Provider acquisition plus exchange plus the startup tailnet-settings read must fit the existing 30-second validation deadline. Typed and generic clients remain independently cached but behaviorally identical.

For HTTP enrollment, obtain a fresh assertion under a 30-second child of the startup context before `tsnet.Start()`. Set `ClientID` and the acquired `IDToken` only, leaving `Audience` empty. For federated HTTP configuration, reject nonempty ambient `TS_AUDIENCE`, `TS_AUTHKEY`, `TS_AUTH_KEY`, or `TS_CLIENT_SECRET` with a sanitized error naming the conflicting variable: tsnet's environment fallback would otherwise conflict with or bypass the selected credential. Do not mutate process environment globally to hide conflicts. Explicit `ClientID` and `IDToken` override their corresponding SDK environment fallbacks.

Enrollment remains a snapshot, with no claim of continuous tsnet provider refresh. The SDK's internal exchange/key minting during `Start()` still has its existing cancellation limitations. Provider acquisition failure or cancellation prevents `Start()` and listener binding; successful setup preserves existing `Up(ctx)`, state isolation, and cleanup.

Stdio acquires provider tokens only through Admin API authentication; it does not acquire a separate enrollment snapshot or require tags. Aperture-only HTTP acquires only the enrollment snapshot and continues to omit Admin API clients, validation, tailnet name, and read scopes. `--version` and `--list-groups` must not inspect token files, load AWS configuration, contact metadata/STS, or initialize tsnet.

### Error handling, operation coverage, and tests

Provider selection is operator configuration, never a tool argument. Acquisition errors identify the provider and stage with static actionable guidance, not token contents, endpoint response bodies, or raw SDK errors. Preserve `context.Canceled` / `context.DeadlineExceeded` for cancellation handling. Provider failure must not fall back to a cached assertion, another provider, or an unconfigured credential. Existing valid access tokens may continue until refresh is needed; there is no partial successful authentication result.

No new paginated or filtered APIs are exposed. Existing Admin API pagination, structured backend errors, MCP tool/resource names, exact grants, and mutation confirmations are unchanged. Token acquisition and exchange may retry only within their bounded provider/SDK policy; never replay the protected Admin API mutation in response to an authentication failure. `make coverage` and production registration tests continue to protect the existing surface.

Tests use synthetic JWTs, rotating temporary files/symlinks, fake metadata transports, fake STS/config boundaries, and mocked Tailscale exchanges. Ordinary tests never touch live cloud metadata, STS, or a tailnet. Live provider smoke tests are optional, explicitly authorized, and must not log tokens or run MCP mutations.

## Risks / Trade-offs

- [Kubernetes issuer is private or token has API-server audience] -> Document publicly reachable issuer/JWKS and dedicated audience projection; fail closed with setup guidance.
- [AWS role permissions or regional STS availability differ] -> Require region and `sts:GetWebIdentityToken` prerequisites; mock contract tests and document verified deployments instead of claiming all AWS regions/platforms work.
- [Ambient SDK credentials select an unexpected AWS principal] -> Document SDK precedence and workload-role setup; never auto-switch between cloud providers.
- [Provider errors contain secrets] -> Sanitize at the acquisition boundary and test secret-bearing errors, panic/log paths, and response bodies.
- [Repeated acquisitions across typed/generic clients and enrollment] -> Accept existing independent access-token caches; avoid a new shared cache with cross-context or stale-token risks.
- [tsnet cannot refresh the assertion callback continuously] -> Document snapshot behavior and require a new process startup for a fresh enrollment attempt; do not imply access-token refresh guarantees node reauthentication.
- [New provider options are ignored by older binaries] -> Require upgrade before changing config and explicit rollback to inline/file credentials; do not mix provider and legacy assertion sources.

## Migration Plan

1. Implement and verify the provider boundary and legacy credential regressions without live services.
2. Add provider examples to the usage guide or a linked, packaged workload-identity guide. Include Kubernetes manifest, AWS role policy, GCP metadata prerequisites, service-toggle examples, and trust setup. Keep examples free of real tokens.
3. Upgrade the binary, configure a matching Tailscale trust and platform identity, then replace only the credential JSON with a provider form. Keep existing MCP grants and appropriate enrollment tags.
4. Validate startup and a permitted read in an explicitly authorized target environment. Record skipped live providers honestly; no live auth-key enrollment or MCP writes are part of automated tests.
5. Roll back by restoring the prior inline/file/OAuth credential form before deploying an older binary. No persisted tsnet-state migration or automatic cloud/trust-policy rollback is introduced.

## Open Questions

No blocking scope questions remain: the user selected Kubernetes, AWS, and GCP, with Azure deferred. Target cloud regions, issuers, audiences, workload claims, and permissions are deployment-specific prerequisites to confirm during optional live smoke testing.

## References

- Tailscale workload identity federation: https://tailscale.com/kb/1581/workload-identity-federation
- AWS outbound identity token claims: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_token_claims.html
- Kubernetes service-account token projection: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection
- Pinned implementation references: `tailscale.com@v1.104.0/wif/wif.go`, `tsnet/tsnet.go`, and `tailscale.com/client/tailscale/v2@v2.11.0/identityfederation.go` in the Go module cache.
