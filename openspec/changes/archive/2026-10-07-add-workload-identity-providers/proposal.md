## Why

Kubernetes and cloud workloads should authenticate from their execution identity without distributing long-lived Tailscale secrets or running a custom token-fetching sidecar. Existing federation only accepts supplied assertions, so operators still have to connect platform token acquisition and rotation to the server themselves.

## What Changes

- Extend the existing federated JSON credential in `TAILSCALE_OAUTH_TOKEN` with explicit `provider` selection: `kubernetes`, `aws`, or `gcp`, plus an audience and provider-specific settings. Keep inline `idToken`, externally managed `idTokenFile`, OAuth, and bearer credentials supported.
- Support Kubernetes projected service-account tokens at a documented, configurable mount path, including kubelet's symlink-based rotation. Kubernetes issues and rotates the token; the application rereads it rather than requesting or writing tokens itself.
- Acquire AWS identity JWTs with regional STS `GetWebIdentityToken` using the AWS SDK credential chain, configured audience, ES384 signing, and a five-minute lifetime. Support role-based EC2/ECS/EKS deployments with the required IAM permission and region configuration.
- Acquire GCP identity JWTs from the attached service account's metadata identity endpoint, for the configured audience. Support environments exposing that endpoint, including appropriately configured GCE/GKE workloads; do not claim universal support for all Google credential types.
- Use context-aware acquisition on Admin API access-token refresh and a bounded pre-tsnet acquisition for enrollment. Retain the existing tsnet assertion-snapshot limitation, and avoid passing both a supplied ID token and an acquisition audience to tsnet.
- Fail closed on ambiguous configuration, unsupported providers, invalid assertions, acquisition failure, and unsafe tsnet credential overrides. Keep provider response bodies and tokens out of diagnostics.
- Preserve independent service toggles, Tailscale-only stdio, offline informational commands, existing permission names, and all tool/resource mappings. Aperture-only HTTP obtains an enrollment assertion but does not initialize or validate Admin API clients.
- Document provider trust prerequisites, least-privilege permissions, projected-token manifests, cloud configuration, refresh boundaries, and offline tests. Native Azure acquisition and automatic provider detection are out of scope for this change.

## Capabilities

### New Capabilities
- `workload-identity-providers`: Explicit provider configuration, Kubernetes/AWS/GCP assertion acquisition, bounded refresh, secure failures, and deployment guidance.

### Modified Capabilities
- `single-oauth-credential-startup`: Extend federated assertion sources, include provider acquisition in authentication deadlines, and configure tsnet with one assertion source while retaining legacy forms and service-aware startup.

## Impact

The main changes affect credential configuration and refresh in `main.go`, a small provider-acquisition module, credential/startup tests, Go dependency declarations for already-transitive AWS SDK packages, and operator documentation. No new MCP tools, resources, or prompts are introduced; provider acquisition is internal authentication behavior, not a caller-invokable credential tool.

Tailscale API scope is limited to the existing `/api/v2/oauth/token-exchange`, tsnet's existing auth-key minting/enrollment flow, and the existing tailnet-settings validation read when Tailscale MCP is enabled. No new Admin OpenAPI operation mappings are added. Kubernetes projected-file and GCP metadata access are reads; AWS STS and Tailscale exchanges issue short-lived credentials, and existing enrollment may mint auth keys/register nodes. Existing MCP read-only versus mutating classifications and confirmation requirements remain unchanged.

Operators must configure a matching Tailscale federated trust (publicly reachable issuer/JWKS, audience, and restricted workload claims), auth-key enrollment scopes/tags for HTTP, and Admin API scopes only for enabled Tailscale MCP operations. Incoming `jaxxstorm.com/cap/mcp` grants and Aperture upstream permissions remain separate from workload identity and do not change.
