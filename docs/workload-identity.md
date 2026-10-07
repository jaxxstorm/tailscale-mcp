# Workload Identity Providers

Use an explicit Kubernetes, AWS, or GCP workload identity instead of distributing a long-lived Tailscale client secret. Upgrade to a binary supporting provider credentials before applying this configuration; older binaries do not support these fields. See the [usage guide](usage.md#credentials) for legacy credentials and general configuration.

## Credential Contract

Set `TAILSCALE_OAUTH_TOKEN` (or `--credential`) to one JSON object:

```json
{"type":"federated","clientId":"<tailscale-client-id>","provider":"kubernetes","audience":"<tailscale-audience>"}
```

```json
{"type":"federated","clientId":"<tailscale-client-id>","provider":"aws","audience":"<tailscale-audience>","region":"us-east-1"}
```

```json
{"type":"federated","clientId":"<tailscale-client-id>","provider":"gcp","audience":"<tailscale-audience>"}
```

| Field | Contract |
| --- | --- |
| `type` | `federated`; may be omitted when a valid provider and `clientId` identify federation |
| `clientId` | Required, nonblank Tailscale federated credential client ID, not the cloud service-account or role ID |
| `provider` | Exactly `kubernetes`, `aws`, or `gcp`; explicit selection, never automatic detection |
| `audience` | Required, nonblank in provider mode; copy the exact audience from the Tailscale trust credential |
| `tokenFile` | Optional Kubernetes-only path; defaults to `/var/run/secrets/tailscale/token` when absent |
| `region` | Optional AWS-only region; when absent, use SDK configuration, then bounded EC2 IMDS discovery |

All these fields are strings. Exactly one assertion source is allowed: inline `idToken`, externally managed `idTokenFile`, or `provider`. Do not combine sources, even as a fallback. Explicitly blank `tokenFile` or `region`, wrong field types, unknown providers, provider fields on OAuth/bearer credentials, `tokenFile` outside Kubernetes, and `region` outside AWS fail validation before provider I/O. `clientId` plus `audience` alone does not select a provider.

Legacy inline/file federation remains supported without an audience, as do existing OAuth and bearer forms. An audience on legacy federation is metadata, not a request for tsnet provider discovery. There is no `auto`, Azure, or GitHub-specific acquisition, arbitrary OIDC login, interactive login, or credential-plugin mechanism. Externally acquired assertions can still use the legacy file form.

## Trust And Permissions

Create a matching [Tailscale federated trust](https://tailscale.com/kb/1581/workload-identity-federation) for the issuer, exact audience, and restricted workload claims. Issuer discovery and JWKS must be publicly reachable by Tailscale; putting the workload on a tailnet does not make a private-only issuer usable. Restrict trust to the intended Kubernetes namespace/service account, AWS account/role, or GCP service account rather than trusting every identity from an issuer.

HTTP enrollment needs permission to create auth keys for `TS_ADVERTISE_TAGS` (for example `tag:mcp-server`). Only an enabled Tailscale MCP service needs `TAILSCALE_TAILNET`, permission for the startup tailnet-settings read, and Admin API scopes for its exposed operations. Aperture-only needs enrollment permissions, not Admin API access.

Workload identity authenticates the server, not incoming MCP callers. Existing `jaxxstorm.com/cap/mcp` grants, exact tool permissions, resource URIs, and mutation confirmations remain unchanged. No MCP tools, resources, prompts, grant names, or Admin API operation mappings are added. Identity assertions are not forwarded to Aperture; its upstream permissions apply to the enrolled MCP node separately.

## Kubernetes

Use a dedicated, audience-specific projected service-account token on a **local projected volume**, mounted read-only. The application reopens the configured path on each acquisition, following kubelet's current symlink target. Kubelet issues and rotates the token; the application never writes tokens or calls the TokenRequest API. No application TokenRequest RBAC is needed. It never falls back to `/var/run/secrets/kubernetes.io/serviceaccount/token` or another identity source.

The following example uses the default token path and requests a 3600-second token lifetime. Replace the image, client ID, tailnet, and both audience placeholders; the two audiences must be identical to the Tailscale trust audience. Configure trust for subject `system:serviceaccount:default:tailscale-mcp`, adjusting the namespace if needed.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tailscale-mcp
  namespace: default
automountServiceAccountToken: false
---
apiVersion: v1
kind: Pod
metadata:
  name: tailscale-mcp
  namespace: default
spec:
  serviceAccountName: tailscale-mcp
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
  containers:
    - name: mcp
      image: your-registry/tailscale-mcp:provider-capable-version
      env:
        - name: TAILSCALE_OAUTH_TOKEN
          value: '{"type":"federated","clientId":"<tailscale-client-id>","provider":"kubernetes","audience":"<tailscale-audience>"}'
        - name: TAILSCALE_TAILNET
          value: yourtailnet.com
        - name: TS_ADVERTISE_TAGS
          value: tag:mcp-server
        - name: TSNET_STATE
          value: file:///var/lib/tailscale-mcp
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
      volumeMounts:
        - name: identity
          mountPath: /var/run/secrets/tailscale
          readOnly: true
        - name: state
          mountPath: /var/lib/tailscale-mcp
  volumes:
    - name: identity
      projected:
        defaultMode: 0440
        sources:
          - serviceAccountToken:
              path: token
              audience: <tailscale-audience>
              expirationSeconds: 3600
    - name: state
      emptyDir: {}
```

Do not use `subPath`: it prevents projected-token rotation from reaching the container. Mount the directory, not an individual token. Restrict volume access to the server UID/group; do not mount it into unrelated containers or copy it into images, logs, or backups. The example's state is ephemeral and pod recreation can enroll a new node; use protected persistent state for production as described under [tsnet state](usage.md#tsnet-state). Kubernetes Secret state is a separate feature with separate API-token/RBAC requirements; the example intentionally uses filesystem state and disables the default API token mount.

An optional `"tokenFile":"/another/local/projection/token"` changes the path, not issuance or rotation ownership. Reads accept only regular files after following projection symlinks. Missing, unreadable, empty, oversized, expired, or wrong-audience files fail closed. Cancellation is checked before and after local I/O, but cannot guarantee interruption of an arbitrary blocked filesystem read; do not use a remote filesystem or pipe.

EKS/GKE operators may explicitly choose this native Kubernetes mode or the appropriate cloud provider mode. The application never switches between them. See [Kubernetes token projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection).

## AWS

Use a workload role with regional STS identity issuance available in the target deployment: an EC2 instance profile, ECS task role (not merely the task execution role), or a correctly configured EKS role. For EKS IRSA, configure the projected AWS web-identity token, `AWS_ROLE_ARN`, and role trust for `AssumeRoleWithWebIdentity`; for EKS Pod Identity, configure the association and agent/container credential endpoint. Those mechanisms supply AWS credentials to the SDK; they are not the final Tailscale assertion.

AWS SDK v2 configuration is loaded lazily and uses its normal refreshable credential chain. Environment credentials and selected shared profiles can take precedence over workload-role credentials; audit `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`, and shared configuration before deploying. Prefer workload roles over static keys. The application's explicit `provider` prevents cross-provider fallback but does not override AWS SDK credential-chain selection.

Region precedence is:

1. JSON `region`.
2. AWS SDK environment/shared configuration, such as `AWS_REGION`, `AWS_DEFAULT_REGION`, or the selected profile's region.
3. Bounded EC2 IMDS region discovery, only if no region was configured.

Configure a region explicitly on ECS/EKS or other environments where EC2 IMDS is unavailable. A configured region avoids region discovery, but the selected credential chain may still need metadata to obtain role credentials.

The application calls regional STS **`GetWebIdentityToken`** with a single audience, **`ES384`**, and **`DurationSeconds: 300`**. This is not a presigned `GetCallerIdentity` request or `AssumeRoleWithWebIdentity`; the latter may occur earlier in the credential chain. The caller role needs the following identity policy, in addition to any permissions/trust needed to obtain the role credentials:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IssueTailscaleIdentityOnly",
      "Effect": "Allow",
      "Action": "sts:GetWebIdentityToken",
      "Resource": "*",
      "Condition": {
        "ForAllValues:StringEquals": {
          "sts:IdentityTokenAudience": ["<tailscale-audience>"]
        },
        "Null": {
          "sts:IdentityTokenAudience": "false"
        },
        "NumericEquals": {
          "sts:DurationSeconds": "300"
        }
      }
    }
  ]
}
```

`Resource: "*"` is required for this issuance action; constrain its audience and duration instead, and avoid another broader allow that defeats these restrictions. This policy does not create the Tailscale trust or grant Admin API access. Confirm regional availability and the role's effective policies (including permission boundaries and organization controls) before deployment. See [AWS outbound identity token claims](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_token_claims.html).

## GCP

Attach the intended service account to the workload and configure Tailscale trust for that identity. Support is limited to environments exposing the attached-service-account identity endpoint, including suitably configured GCE and GKE workloads. On GKE, enable/configure the metadata identity integration and service-account mapping/permissions required by your deployment; a Kubernetes service account or arbitrary Google credential file alone is insufficient. Ensure the workload can reach the metadata server and obtain an identity token for the configured audience.

The production endpoint is fixed:

```text
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity
```

The request adds URL-encoded `audience=<tailscale-audience>` and `format=full`, with `Metadata-Flavor: Google`. A successful response must be HTTP 200 with the same metadata header and a valid identity JWT. `GCE_METADATA_HOST` and other endpoint overrides do not change this endpoint. Redirects and environment proxies are disabled.

There is no fallback to user Application Default Credentials (ADC), service-account key files, IAM service-account impersonation, another attached account selector, or another cloud. Grant only the platform permissions needed to attach/use the intended service account; the application does not call IAM Credentials APIs to mint tokens. See [Google identity token guidance](https://cloud.google.com/docs/authentication/get-id-token).

## Refresh And Startup

All three provider sources observe the initiating context with a maximum 30-second acquisition budget, shortened by any earlier caller deadline. Cloud HTTP requests have at most five seconds per request, finite retries within the overall budget, no redirects or ambient proxies, and normal TLS verification for HTTPS. Acquired tokens and metadata/file bodies are limited to 1 MiB; overflow is rejected, not truncated.

Provider output is trimmed and checked for compact JWT format, decodable claims, a future numeric `exp`, and matching `aud` (a string or member of a string array). These are sanity checks, not signature or issuer verification. Tailscale remains responsible for signature, issuer, subject, and trust-claim verification; decoded claims never authorize MCP callers.

| Authentication boundary | Behavior |
| --- | --- |
| Admin API access-token refresh | Each typed/generic client reuses its valid cached Tailscale access token. When refresh is needed, it acquires a current provider assertion and exchanges it at `/api/v2/oauth/token-exchange` under the initiating request context. The clients have independent access-token caches; provider JWTs are not cached for later refresh. |
| Tailscale-enabled startup | Provider acquisition, exchange, and the tailnet-settings validation read share the existing 30-second validation deadline. This applies to HTTP and stdio. |
| HTTP tsnet enrollment | A separate current assertion is acquired before `tsnet.Start()` under the startup context and a maximum 30-second acquisition budget. tsnet receives only `ClientID` and the supplied `IDToken`, not its competing `Audience` acquisition selector. |
| Node reauthentication | tsnet retains a startup assertion snapshot. Provider acquisition and Admin API refresh do not continuously replace it or guarantee node reauthentication. Start a new process for a fresh enrollment attempt when needed. |

Kubelet owns Kubernetes issuance/rotation; the application reads the current projection. AWS/GCP assertions are obtained on demand by the application. Legacy `idTokenFile` issuance/rotation remains externally managed with protected files and atomic replacement; inline assertions do not rotate. None of these sources guarantees continuous tsnet assertion refresh.

Acquisition failure or cancellation before `Start()` prevents enrollment and listener binding. The pinned SDK's `Start()` and its internal exchange/auth-key minting do not accept a context; cancellation during that phase is handled after initialization returns. The 30-second acquisition/validation bounds are not an overall tsnet startup deadline. Existing readiness cancellation, state isolation, and cleanup still apply.

### Service Modes

With the credential configured, select services independently:

```bash
./ts-mcp                              # Tailscale-only HTTP (default)
./ts-mcp --aperture                    # Combined HTTP
./ts-mcp --tailscale=false --aperture  # Aperture-only HTTP
./ts-mcp --stdio --local-grants '{"tools":["list_all_devices"],"resources":[]}'
```

Tailscale-only and combined HTTP need Admin API access plus tagged enrollment. Aperture-only HTTP acquires only the enrollment snapshot: it creates no Admin API clients, performs no Admin API validation, and needs neither `TAILSCALE_TAILNET` nor Admin API read scopes. Its enrolled node still needs [Aperture upstream permissions](aperture.md#grants-and-discovery), separately from incoming MCP grants.

Stdio is Tailscale-only and acquires assertions through Admin API authentication, with no separate enrollment snapshot, tsnet, or advertised-tag requirement. Both services disabled is invalid for serving; disabling Tailscale is invalid for stdio. `--version` and every enabled-service `--list-groups` combination remain offline: no token-file reads, AWS configuration loading, metadata/STS calls, or tsnet initialization.

### Environment Conflicts

For **all federated HTTP credentials**, including legacy inline/file forms, nonempty `TS_AUDIENCE`, `TS_AUTHKEY`, `TS_AUTH_KEY`, or `TS_CLIENT_SECRET` now cause an explicit startup conflict before acquisition/enrollment. Remove these competing values from the process deployment environment; they could otherwise conflict with or bypass the selected credential. Errors name the variable without its value. The application does not globally unset variables to hide conflicts.

Explicit `ClientID` and the acquired `IDToken` override the corresponding tsnet `TS_CLIENT_ID` and `TS_ID_TOKEN` fallbacks. Unrelated environment variables are not rejected. Stdio does not use tsnet and is unaffected by these tsnet-only conflict checks. AWS SDK credential-chain environment selection remains separate from these rules.

## Diagnostics And Rollback

Errors identify provider/stage and setup guidance without assertions, credentials, provider response bodies, or raw SDK errors. Check configuration, file access/rotation, region/role permissions, metadata availability, and issuer/audience/trust before retrying; never paste tokens or decoded payloads into logs or bug reports. Cancellation/deadline errors remain distinguishable.

A failed acquisition never switches providers, uses a prior assertion, or dispatches/replays the protected Admin API mutation. An already-valid cached access token may continue to work until it needs refresh. Incoming grants and mutation confirmations are unchanged.

Upgrade the binary before replacing legacy credential JSON with provider JSON. To roll back, restore the prior inline `idToken`, externally managed `idTokenFile`, OAuth, or bearer credential **before** deploying an older binary. Remove `provider`, `tokenFile`, and `region`; do not combine old and new assertion sources. Preserve appropriate scopes, tags, file protection, and external refreshers. There is no persisted tsnet-state migration or automatic rollback of cloud policies, Tailscale trust, enrolled nodes, or upstream writes.

Live Kubernetes, AWS, and GCP smoke tests are optional and require explicit operator authorization, a provider-capable binary, matching trust, platform identity/permissions, and an approved target tailnet. They may issue credentials and enroll nodes; they are not offline checks. No live provider authentication or enrollment was performed for this documentation change. Do not print tokens or invoke MCP mutations as part of verification.
