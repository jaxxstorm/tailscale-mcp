# Usage Guide

## Prerequisites

* [Tailscale](https://tailscale.com) account with an OAuth or federated credential
* The Go toolchain declared in `go.mod` if building from source (CI uses that file too)

## Installation

Download the latest pre-built binary for your platform from the release page, or build from source:

```bash
git clone <repo_url>
cd <repo_dir>
go build -o ts-mcp .
```

You can also install with Homebrew:

```bash
brew install jaxxstorm/tap/tailscale-mcp
```

## Configuration

Required environment variables for default Tailscale-enabled tailnet HTTP with OAuth credentials:

```bash
export TAILSCALE_OAUTH_TOKEN='{"type":"oauth","clientId":"k123...","clientSecret":"tskey-client-...","scopes":["all"]}'
export TAILSCALE_TAILNET="yourtailnet.com"
export TS_ADVERTISE_TAGS="tag:mcp-server"
```

Optional environment variables:

```bash
export TS_HOSTNAME="ts-mcp"
export TSNET_STATE="file://"
export TS_MCP_TAILSCALE=true
export TS_MCP_APERTURE=false
export APERTURE_URL="http://ai/aperture"
```

Leave `TS_PORT` unset to use the TLS-dependent default; setting it explicitly overrides that default, just like `--port`.

`TS_ADVERTISE_TAGS` is required for tailnet HTTP when `TAILSCALE_OAUTH_TOKEN` is an OAuth client secret or federated credential because tsnet mints a tagged node auth key during startup. The OAuth client or federated credential must be allowed to create auth keys for the advertised tag. Stdio never starts tsnet or requires advertised tags, but still requires the tailnet and Admin API credentials and validates their access before serving.

Command line options:

* `--debug` / `-d`: Enable debug logging
* `--version` / `-v`: Show version information offline, without credentials or network initialization
* `--list-groups`: Print deterministic tool names, groups, and read-only classification for enabled services, excluding Aperture with `--stdio`, then exit offline without credentials, tsnet startup, schema downloads, or upstream calls; an empty `[]` is allowed
* `--oauth-client-id`: OAuth client ID to use when `TAILSCALE_OAUTH_TOKEN` is a raw `tskey-client-*` secret
* `--advertise-tags`: Comma-separated Tailscale tags to advertise when minting tsnet auth keys from OAuth or federated credentials
* `--state`: tsnet state location. Same as `TSNET_STATE`
* `--stdio`: Use deprecated Tailscale-only stdio compatibility mode instead of Streamable HTTP; Aperture enablement and URL are ignored, with no URL validation or Aperture client or tools initialized
* `--tailscale` / `TS_MCP_TAILSCALE`: Boolean Tailscale MCP enablement, default `true`; `--tailscale=false` overrides an environment value of `true`. Disables the MCP service, not shared tsnet transport or identity
* `--aperture` / `TS_MCP_APERTURE`: Boolean HTTP Aperture opt-in, default `false`; `--aperture` or `--aperture=true` enables its route, tools, upstream client, and startup endpoint URL logs. `--aperture=false` overrides an environment value of `true`
* `--aperture-url` / `APERTURE_URL`: Operator-configured Aperture API base URL, default `http://ai/aperture`; not an MCP endpoint or tool argument. Setting it alone does not enable Aperture
* `--local-grants` / `TS_MCP_LOCAL_GRANTS`: A single JSON object with `tools` and `resources` arrays of strings; unset or empty grants authorize nothing
* `--local-http` / `TS_MCP_LOCAL_HTTP`: Enable additional loopback HTTP, default `false`; requires HTTP mode and an explicit non-empty local grant
* `--local-port` / `TS_MCP_LOCAL_PORT`: Loopback port, default `8080`, independent of tailnet TLS and port
* `--tls` / `TS_TLS`: Enable tailnet HTTPS, default `false`; does not enable TLS on loopback
* `--port` / `TS_PORT`: Tailnet port; defaults to `443` with TLS or `8080` without TLS unless explicitly set

Ports must be integers from 1 through 65535. Invalid ports, malformed local JSON, unknown fields, invalid field types, and contradictory listener options fail startup. Local grants are not a capability-key wrapper or an array of entries: use `{"tools":["list_all_devices"],"resources":[]}`. Configuring grants alone never opens loopback, and local grants never authorize tailnet callers.

When Aperture is disabled, its URL is not validated, no upstream Aperture client or tools are initialized, no Aperture endpoint URLs are logged, and `/aperture/mcp` returns 404 on both tailnet and enabled loopback listeners. Tailscale routes and behavior are unchanged. When enabled for HTTP serving, the Aperture base must be a complete HTTP(S) URL without userinfo, query, or fragment; invalid values fail before serving. A trailing slash is normalized without losing the base path, so `http://ai/aperture/` still targets operations under `/aperture`. Both enabled MCP services remain available when Aperture is unreachable; there is no live Aperture startup probe. See [Aperture identity and tools](aperture.md).

## tsnet State

`TSNET_STATE` controls where the embedded tsnet node stores its Tailscale identity and local state.

If `TSNET_STATE` is unset, the default is unchanged from earlier releases: state is stored in a hostname-specific directory under the process working directory. With the default `TS_HOSTNAME=ts-mcp`, the state file is:

```text
./tsnet-ts-mcp/tailscaled.state
```

The server logs the resolved state location at startup as `Configured tsnet state`, including the absolute filesystem path when state is file-backed.

State contains node identity material. Protect its directory and backups, use fresh or operator-owned state only, and never copy fork state into a deployment. Keep custom state directories and credential files outside the source/build tree. Default `tsnet-*` directories are ignored; Docker and release packaging explicitly limit their inputs.

Supported values:

* `file://`: use the default hostname-specific directory, such as `./tsnet-ts-mcp/tailscaled.state`
* `file:///var/lib/tailscale-mcp`: store filesystem state at `/var/lib/tailscale-mcp/tailscaled.state`
* `kube://tailscale-mcp-state`: store state in the Kubernetes Secret `tailscale-mcp-state`
* `aws://us-east-1/123456789012/parameter/tailscale/mcp`: store state in AWS SSM Parameter Store
* `aws://arn:aws:ssm:us-east-1:123456789012:parameter/tailscale/mcp`: store state in the given AWS SSM ARN

The native Tailscale store prefixes are also accepted for compatibility: `kube:<secret>`, `arn:aws:ssm:...`, and `mem:`.

Kubernetes Secret state requires the pod service account to have `get` and `update` on the state Secret. Grant `patch` and `create` as well so the store can efficiently update or create the Secret. Optional Kubernetes Events require `get`, `create`, and `patch` on `events`.

Example Kubernetes RBAC:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: tailscale-mcp-state
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["tailscale-mcp-state"]
    verbs: ["get", "update", "patch"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["get", "create", "patch"]
```

When using Kubernetes state:

```bash
export TSNET_STATE="kube://tailscale-mcp-state"
```

When using AWS SSM state, the workload must have AWS credentials that can read and write the target parameter. If `kmsKey` is provided, the workload also needs permission to use that key:

```bash
export TSNET_STATE="aws://us-east-1/123456789012/parameter/tailscale/mcp?kmsKey=alias/tailscale-state"
```

## Credentials

Create a Tailscale OAuth client or federated credential for tsnet enrollment in HTTP mode. When Tailscale MCP is enabled, it must also read tailnet settings at startup and perform every Admin API operation you expose through MCP. Aperture-only HTTP still needs `TAILSCALE_OAUTH_TOKEN` and advertised tags where applicable, but does not require `TAILSCALE_TAILNET` or Admin API read scopes.

OAuth client JSON form:

```bash
export TAILSCALE_OAUTH_TOKEN='{"type":"oauth","clientId":"k123...","clientSecret":"tskey-client-...","scopes":["all"]}'
export TS_ADVERTISE_TAGS="tag:mcp-server"
```

OAuth client split form:

```bash
export TAILSCALE_OAUTH_TOKEN="tskey-client-..."
export TAILSCALE_OAUTH_CLIENT_ID="k123..."
export TS_ADVERTISE_TAGS="tag:mcp-server"
```

Federated JSON form:

```bash
export TAILSCALE_OAUTH_TOKEN='{"type":"federated","clientId":"k123...","idToken":"<oidc-id-token>"}'
export TS_ADVERTISE_TAGS="tag:mcp-server"
```

A raw bearer/auth-key-like token is also accepted for deployments where the same token can authenticate Admin API requests and tsnet startup:

```bash
export TAILSCALE_OAUTH_TOKEN="tskey-..."
```

For an externally rotated federated assertion, use a file instead of inline `idToken`:

```bash
export TAILSCALE_OAUTH_TOKEN='{"type":"federated","clientId":"k123...","idTokenFile":"/run/tailscale-mcp/id-token"}'
```

Federated JSON requires `clientId` and exactly one of `idToken`, `idTokenFile`, or an explicit `provider`; mixed sources or no source are errors. For the legacy `idTokenFile` form, an external identity-provider refresher must acquire tokens and atomically replace the file: write a complete new token to a restricted temporary file in the same directory, then rename it over the configured path. Do not truncate/rewrite the live file. Restrict ownership and permissions on both file (for example `0600`) and parent directory (for example `0700`) to the server/refresher identities, including during replacement. Never log tokens or place them in the repository, image, or release archive.

Both typed and generic Admin API clients reread and trim the file whenever federation needs a new assertion. A cached valid access token may be reused, so this is not a reread on every API request. Missing, unreadable, or empty files fail authentication without falling back to a stale assertion. Existing inline, OAuth, and bearer credential forms remain supported.

For platform-managed identity, upgrade to a provider-capable binary and select `provider: "kubernetes"`, `"aws"`, or `"gcp"` with required nonblank `clientId` and `audience`. Kubernetes accepts optional `tokenFile` (default `/var/run/secrets/tailscale/token`); AWS accepts optional `region`. These options are provider-specific and explicitly blank values are invalid. There is no automatic detection, cross-provider fallback, Azure, or GitHub-specific acquisition. See the [workload identity guide](workload-identity.md) for complete JSON examples, trust prerequisites, a read-only Kubernetes projection manifest, AWS permissions/region precedence, and GCP attached-service-account metadata setup.

tsnet uses a startup snapshot of the assertion, not continuous provider or file refresh. Legacy file mode does not obtain OIDC tokens automatically; kubelet rotates Kubernetes projections, while AWS/GCP provider mode acquires tokens on demand. Both Admin API clients acquire a current provider assertion when their cached access token needs refresh, not on every request. All three provider sources observe the caller context with a maximum 30-second acquisition budget. HTTP obtains a separate snapshot before `tsnet.Start()` under the startup context and that budget; failure or cancellation prevents enrollment. tsnet receives only the client ID and supplied assertion, not an audience selector. The SDK's internal `Start()` exchange/enrollment still has cancellation limitations; restart for a fresh enrollment assertion when needed.

Federated HTTP now rejects nonempty ambient `TS_AUDIENCE`, `TS_AUTHKEY`, `TS_AUTH_KEY`, and `TS_CLIENT_SECRET` before acquisition/enrollment, naming variables without logging values or globally unsetting them. Remove these competing settings from the deployment environment. Explicit client ID/assertion values override `TS_CLIENT_ID`/`TS_ID_TOKEN` fallbacks. Stdio is unaffected by tsnet-only conflicts and obtains no enrollment snapshot.

When Tailscale MCP is enabled, HTTP and stdio validate Admin API access with the existing low-risk tailnet-settings read under a shared 30-second deadline covering provider acquisition, exchange, and the read; retain permission for that read even when exposing only narrow Tailscale tool grants. Aperture-only HTTP skips Admin API client initialization and validation and needs only the enrollment snapshot, not Admin API scopes or a tailnet name. These bounds are not a guarantee that all tsnet startup completes within 30 seconds. Provider/exchange failures are sanitized and never trigger identity fallback or replay a protected mutation. No MCP tools, resources, prompts, or grant names are added. See [diagnostics and credential rollback](workload-identity.md#diagnostics-and-rollback) before reverting to an older binary.

For full OpenAPI coverage, grant the credential scopes or permissions for devices, DNS, policy files, tailnet settings, users, invites, keys, webhooks, services, logging, OAuth apps, and posture integrations. Mutating MCP tools also require the operation-specific `confirm` argument and matching Tailscale API write permissions.

Aperture-only startup uses `--tailscale=false --aperture`; it is not credential-free and retains shared tsnet enrollment and identity requirements. Aperture requests use the running MCP tsnet node's identity, without relying on a host Tailscale daemon or forwarding the Admin API credential, incoming cookies, or caller identity headers. Grant that node upstream admin for configuration operations and explicit `read_pricing: true` for pricing, even if it is an admin. These roles do not grant downstream MCP access; callers still need the separate tool permissions described in the [Aperture guide](aperture.md#grants-and-discovery).

## OAuth Grants And Access Control

The server uses Tailscale grants with the custom MCP capability `jaxxstorm.com/cap/mcp`. These grants control incoming MCP user access and are separate from the server credential's Tailscale Admin API scopes.

Example ACL policy:

```json
{
  "grants": [
    {
      "src": ["user:alice@example.com"],
      "dst": ["tag:mcp-server"],
      "app": {
        "jaxxstorm.com/cap/mcp": [{
          "tools": ["*"],
          "resources": ["*"]
        }]
      }
    },
    {
      "src": ["user:bob@example.com"],
      "dst": ["tag:mcp-server"],
      "app": {
        "jaxxstorm.com/cap/mcp": [{
          "tools": ["list_all_devices"],
          "resources": ["bootstrap://status", "tailscale://devices"]
        }]
      }
    }
  ]
}
```

Tool grants:

* `get_device_info`: Allow querying specific device details
* `list_all_devices`: Allow listing all devices
* `tailscale_<operation>`: Allow a generated Tailscale API tool, for example `tailscale_get_dns_configuration`
* `aperture_<operation>`: Allow an exact Aperture tool, for example `aperture_get_pricing`; see the [five-tool mapping](aperture.md#tools-and-inputs)
* `*`: Allow all tools
* `read:*`: Allow all registered tools classified as read-only by server metadata
* `group:<name>`: Allow registered readers and writers in that group, for example `group:dns`
* `group:<name>:read`: Allow only registered readers in that group, for example `group:dns:read`

Tool selectors have **OR semantics**, not intersection: `["read:*", "group:dns"]` permits every registered reader plus DNS writers. Unknown groups and unsupported selectors match nothing; arbitrary glob syntax is not supported. Read-only classification comes from trusted registration metadata, not the tool name. Authorized mutations still require their confirmation tokens and upstream write permissions; Aperture replacement additionally requires a concrete ETag.

**Enabling Aperture expands existing wildcard grants:** Only when Aperture is enabled in HTTP mode, `*` includes all five Aperture tools and `read:*` includes config get/validation and both pricing reads, but not replacement. `group:aperture-config` includes replacement; `group:aperture-config:read` excludes it. Both `group:aperture-pricing` and `group:aperture-pricing:read` permit the two pricing readers. Existing exact Tailscale names and Tailscale groups do not match Aperture. No grant enables disabled tools. Audit both tailnet and local grants before enabling Aperture; only then does the broad Alice example above include Aperture access.

Read-only is not non-sensitive: readers can expose policy, device/user information, logs, or key material visible to the server credential. Global, read, and group selectors can broaden permissions when matching tools are added on upgrade. Prefer exact tool names for tightly controlled deployments and review catalog changes before upgrading.

Tool and group names are stable permission identities. Inspect the actual configured surface without credentials or network access:

```bash
./ts-mcp --list-groups
./ts-mcp --list-groups --aperture
./ts-mcp --list-groups --tailscale=false --aperture
./ts-mcp --list-groups --tailscale=false --aperture=false  # []
./ts-mcp --list-groups --stdio --tailscale=false --aperture  # []
TS_MCP_APERTURE=true ./ts-mcp --list-groups --aperture=false
./ts-mcp --list-groups --stdio
TAILSCALE_LOCAL_CLI=1 ./ts-mcp --list-groups
```

Local CLI diagnostics are off by default; selectors cannot register or enable them. `--list-groups` reports the configured registered surface, not a caller-filtered list. MCP `tools/list` is filtered to the current caller's grants, and unauthorized direct `tools/call` requests are rejected too. Matching tailnet capability entries are unioned; malformed entries fail closed. Client headers cannot supply identity or grants.

Resource grants:

* `bootstrap://status`: Health check endpoint
* `tailscale://devices`: Device list resource
* `tailscale://policy`: Policy file access
* `tailscale://tailnet-settings`: Tailnet settings access
* `tailscale://device`: Individual device resource access
* `tailscale://dns/*`, `tailscale://keys`, `tailscale://webhooks`, `tailscale://services`, `tailscale://oauth-apps`, and similar read API resources
* `*`: Allow all resources

Resource permissions are separate: even `tools: ["*"]` or `tools: ["read:*"]` grants no resource access. Resource discovery is not filtered by tool selectors; a listed resource still requires authorization to read.

### Resource-Prefix Migration

Resources now match exact URIs, global `*`, or an explicit trailing `/*` for non-empty descendants. Empty selectors never match. Replace policies that relied on implicit prefixes before upgrading:

| Intent | Resource grant |
|--------|----------------|
| Only the device collection | `tailscale://devices` |
| Only descendants | `tailscale://devices/*` |
| Collection and descendants | Both `tailscale://devices` and `tailscale://devices/*` |
| One resource | Its exact registered URI, such as `tailscale://dns/configuration` |

`tailscale://devices/*` matches `tailscale://devices/123`, but not `tailscale://devices`, `tailscale://devices/`, or `tailscale://devices-other/123`. Exact `tailscale://device` does not grant `tailscale://devices` or descendants of either. Selectors authorize existing resources; they do not create new endpoints. Existing exact tool grants, curated wrappers, names, schemas, resource URIs, and mutation confirmations are unchanged. No profiles or profile URLs are introduced.

## Running The Server

Streamable HTTP is the default transport:

```bash
./ts-mcp
```

By default the tailnet listener exposes `http://<hostname>.yourtailnet.ts.net:8080/tailscale/mcp` and its `/mcp` alias; no loopback listener opens and Aperture is disabled. `/tailscale/mcp` is the preferred explicit Tailscale route; `/mcp` remains a backward-compatible alias without a redirect, using the same Tailscale handler, server, catalog, and session state. Both Tailscale paths receive identical grants and transport protections on tailnet and enabled loopback listeners.

To also enable Aperture on the same listener and port:

```bash
./ts-mcp --aperture=true
```

This adds `http://<hostname>.yourtailnet.ts.net:8080/aperture/mcp`. Tailscale and Aperture are independent MCP servers with separate catalogs and sessions. Tailscale tools, resources, and prompts exist only on the Tailscale surface; enabled Aperture has only its five tools and adds no resources or prompts. Calls to the wrong service are unavailable, and session IDs do not transfer state or permissions between services.

To serve Aperture only, with the existing tsnet enrollment credential and advertised tags where applicable configured:

```bash
./ts-mcp --tailscale=false --aperture
```

Both `/mcp` and `/tailscale/mcp` return 404 on tailnet and enabled loopback listeners. Tailscale tools, resources, prompts, and Admin API clients are not initialized, Admin API validation is skipped, and no Tailscale MCP endpoint URLs are logged. Neither `TAILSCALE_TAILNET` nor Admin API read scopes are required; shared tsnet transport and identity remain active. Grants cannot enable disabled services.

Serving with both services disabled fails before any network access. Stdio requires Tailscale enabled: `--stdio --tailscale=false` fails before network access even with `--aperture`. Informational `--version` and `--list-groups` bypass these serving checks and remain offline; listing includes only enabled services, ignores Aperture in stdio, and returns `[]` when no services are included.

To enable tailnet HTTPS:

```bash
./ts-mcp --tls
```

Enable MagicDNS and HTTPS certificates in the tailnet and use the node's fully qualified `*.ts.net` name. Tailscale-issued certificates can publish that DNS name in public certificate transparency logs; choose the hostname accordingly. TLS listener/certificate failures never fall back to plaintext. The default HTTPS URL is `https://<hostname>.yourtailnet.ts.net:443/tailscale/mcp` (also available via `/mcp`). Running `./ts-mcp --tls --aperture` additionally serves `https://<hostname>.yourtailnet.ts.net:443/aperture/mcp`; `--tls --port 8443` changes all enabled tailnet routes to port 8443. Use the full endpoint URLs logged at startup; Aperture URLs are logged only when Aperture is enabled in HTTP mode.

Tailnet HTTP Host checks accept only the ready node's full/short DNS name or Tailscale IPs at the configured port. Arbitrary DNS aliases and reverse-proxy Host overrides are rejected, even with a matching Origin. For HTTPS, use the fully qualified certificate name. Forwarded headers do not establish the expected hostname, scheme, or caller identity.

Tailnet readiness and listener acquisition observe shutdown cancellation. The SDK's initial `tsnet.Start()` call does not accept a context and cannot safely be interrupted by closing the partially initialized server; cancellation during that phase is handled after initialization returns. The Admin API validation deadline is not an overall tsnet startup deadline.

To additionally enable loopback with narrow permissions:

```bash
./ts-mcp --tls --local-http --local-port 8081 \
  --local-grants '{"tools":["list_all_devices"],"resources":["bootstrap://status"]}'
```

This leaves the Tailscale tailnet HTTPS routes on port 443 and adds plain HTTP at `http://127.0.0.1:8081/tailscale/mcp` and its `/mcp` alias. Adding `--aperture` would also enable `/aperture/mcp` on both listeners, but the example grants no Aperture access. Without `--local-port`, loopback uses 8080 even with TLS. Loopback binds only `127.0.0.1`, but **every process able to connect receives the same local grants**. This is not same-user authentication or a multi-user service. Avoid it on untrusted shared hosts and do not proxy or forward it to other users. Host/DNS-rebinding and Origin checks do not authenticate local processes. All enabled routes use only these local grants on loopback; they never authorize tailnet callers.

When present, Origin must be a single HTTP(S) origin matching the listener's scheme, hostname, and effective port. Lookalike hosts, `null`, paths, queries, fragments, and multiple origins are rejected. Forwarded headers do not override identity or scheme. Non-browser clients may omit Origin, but still undergo Host and grant checks.

Deprecated stdio compatibility mode is available for older local clients that cannot use Streamable HTTP yet:

```bash
./ts-mcp --stdio --local-grants '{"tools":["list_all_devices"],"resources":[]}'
```

Stdio is Tailscale-only: it opens no HTTP listeners, registers no Aperture tools, and never initializes tsnet or the Aperture client or requires advertised tags. It ignores `--aperture` / `TS_MCP_APERTURE` and the Aperture URL, without validating that URL, even when explicitly enabled. It still validates Admin API credentials and denies protected operations without local grants. Do not combine stdio with local HTTP opt-in. Use Streamable HTTP with `--aperture` for Aperture.

### Limits And Shutdown

Both HTTP service routes share Host/Origin checks and transport limits. HTTP POST bodies are limited to **4 MiB**, including chunked bodies and requests from peers without MCP grants. Header reads have a **10-second** timeout, body reads a **30-second** deadline, and idle keep-alive connections a **120-second** timeout. Oversized or slow bodies fail before operation dispatch; account for JSON encoding overhead when submitting large ACL policies or Aperture configuration. The body deadline is cleared after consumption and is not a tool-execution or SSE-stream deadline.

SIGINT/SIGTERM stops both listeners, cancels request/stream contexts, and drains within one shared **10-second** shutdown budget before force-closing remaining connections and cleaning up tsnet. Unexpected serving failures exit nonzero after cleanup. An interrupted mutation has an **ambiguous outcome**: cancellation is not rollback, and the upstream operation may already have applied. Do not automatically retry. Inspect authoritative state, ETags, and available audit records before deciding whether another confirmed write is needed.

## Claude Desktop Integration

Use Claude Desktop's Streamable HTTP remote MCP configuration when available. Create entries only for enabled services, using separate entries on the same host and port when both are enabled. Every Tailscale URL below requires Tailscale enabled (the default); every Aperture URL requires `--aperture` (or `TS_MCP_APERTURE=true`), and loopback additionally requires explicit local HTTP opt-in with narrow grants:

| Listener | Tailscale Client URL | Aperture Client URL |
|---|---|---|
| Tailnet HTTP with `--aperture` | `http://<hostname>.yourtailnet.ts.net:8080/tailscale/mcp` | `http://<hostname>.yourtailnet.ts.net:8080/aperture/mcp` |
| Tailnet with `--tls --aperture` | `https://<hostname>.yourtailnet.ts.net:443/tailscale/mcp` | `https://<hostname>.yourtailnet.ts.net:443/aperture/mcp` |
| Loopback with `--aperture --local-http --local-port 8081` | `http://127.0.0.1:8081/tailscale/mcp` | `http://127.0.0.1:8081/aperture/mcp` |

While Tailscale is enabled, existing `/mcp` URLs continue to work without redirects; use `/tailscale/mcp` for new configurations as the preferred explicit route. The two Tailscale paths share session state, but every request uses its current trusted grants. Each entry discovers only its service's authorized tools. Use separate sessions for Tailscale and Aperture; a session ID is neither a cross-service handle nor an authorization credential. With `--tailscale=false --aperture`, configure only the Aperture entry.

For older Claude Desktop versions that only support local stdio MCP servers, use the deprecated Tailscale-only compatibility mode temporarily (this cannot expose Aperture):

```json
{
  "mcpServers": {
    "tailscale": {
      "command": "/usr/local/bin/ts-mcp",
      "args": ["--stdio"],
      "env": {
        "TAILSCALE_OAUTH_TOKEN": "{\"type\":\"oauth\",\"clientId\":\"k123...\",\"clientSecret\":\"tskey-client-...\",\"scopes\":[\"all\"]}",
        "TAILSCALE_TAILNET": "yourtailnet.com",
        "TS_MCP_LOCAL_GRANTS": "{\"tools\":[\"list_all_devices\"],\"resources\":[]}"
      }
    }
  }
}
```

## Tools And Resources

When Tailscale is enabled, the following Tailscale tools and resources are on `/tailscale/mcp` and its backward-compatible `/mcp` alias (or deprecated stdio). They are absent when Tailscale is disabled, including optional local CLI tools regardless of `TAILSCALE_LOCAL_CLI`. For the five tools on `/aperture/mcp` when enabled with `--aperture`, see [Aperture tools, inputs, and safety workflow](aperture.md). Aperture adds no resources or prompts.

Core tools:

| Tool | Description | Arguments | Required Grant |
|------|-------------|-----------|----------------|
| `get_device_info` | Fetch device details by ID, IP, or hostname | `device`: Device identifier | `get_device_info` |
| `list_all_devices` | List all devices in your tailnet | None | `list_all_devices` |

Additional Tailscale API tools are generated from endpoint definitions using `tailscale_<operation>` grant names. Examples include `tailscale_get_dns_configuration`, `tailscale_list_users`, `tailscale_get_key`, `tailscale_list_webhooks`, `tailscale_list_services`, `tailscale_get_oauth_app`, and `tailscale_validate_and_test_policy_file`.

Generated tools cover the full Tailscale OpenAPI snapshot. Mutating create/update/delete tools require a `confirm` argument whose value is the OpenAPI operation ID, for example `confirm: "deleteDevice"`. This is in addition to Tailscale MCP grants and Admin API token permissions.

### Composable Endpoint Workflows

Every mapped Tailscale OpenAPI operation is available as a first-class MCP primitive, either as a tool or a resource. Agents can compose these primitives the same way an operator might compose `curl` calls: read tailnet state, inspect the JSON result, choose the next endpoint, and propose a guarded write when needed.

Generated endpoint tools include MCP safety hints for clients that support mutation gating:

* `readOnlyHint=true`: The tool is expected not to change Tailscale state. GET operations and read-like validation operations use this hint.
* `destructiveHint=true`: The tool may delete, revoke, expire, suspend, rotate, or otherwise destructively change Tailscale state.
* `idempotentHint=true`: Repeating the same tool call with the same inputs is expected not to create additional side effects.

These hints are advisory metadata for MCP clients. Server-side enforcement remains authoritative: every tool and resource still requires the configured `jaxxstorm.com/cap/mcp` grant, and mutating tools still require the exact `confirm` token for the underlying OpenAPI operation.

### Network Flow Logs

`tailscale_list_network_flow_logs` returns network flow logs in chronological windows of at most five minutes so a busy tailnet cannot overwhelm an MCP client's context. For the first call, provide RFC3339 `start` and `end` timestamps. The response contains `logs`, the effective window `start` and `end`, and `nextCursor` when more of the requested range remains. Call the tool again with that value as `cursor` until `nextCursor` is absent.

The tool remains read-only and accepts the exact `tailscale_list_network_flow_logs` tool grant or a matching tool selector.

### Alpha Organization Lifecycle

These three APIs are **Alpha** and their upstream contracts may change. They are canonical tools in the separate `organizations` group; no new resources, prompts, or curated aliases are added.

| Tool / Exact Tool Grant | Upstream Operation | Required Confirmation | Upstream OAuth Scope |
|---|---|---|---|
| `tailscale_list_organization_tailnets` | `GET /organizations/{organization}/tailnets` | None | `tailnets:read` |
| `tailscale_create_organization_tailnet` | `POST /organizations/{organization}/tailnets` | `createOrganizationTailnet` | `tailnets` |
| `tailscale_delete_tailnet` | `DELETE /tailnet/{tailnet}` | `deleteTailnet` | `all` |

Upstream scopes authorize the **server credential**, not the MCP caller. They do not replace `jaxxstorm.com/cap/mcp` grants. With Tailscale MCP enabled, HTTP and stdio first read settings for `TAILSCALE_TAILNET`; tailnet HTTP also requires authority to mint the tagged tsnet auth key and `TS_ADVERTISE_TAGS`. Organization-only credentials with `tailnets:read` or `tailnets` may therefore fail startup even if they can invoke the organization endpoint directly. Disabling Tailscale MCP skips that read but also removes all organization tools; it is not an organization-only startup mode or separate per-tool credential mechanism.

#### Listing One Page

Example MCP `tools/call` parameters:

```json
{
  "name": "tailscale_list_organization_tailnets",
  "arguments": {"organization": "-", "limit": 25}
}
```

`organization` must be a nonblank string; `-` selects the credential's current organization. An explicit organization is escaped as one path segment. `limit` must be an integer from 1 through 100; omitting it leaves the upstream default of 100. Optional `cursor` must be a string. Each invocation makes one page request and preserves `tailnets`, `cursor`, and `totalCount`; it never automatically fetches subsequent pages. Use the returned opaque cursor unchanged for the next call:

```json
{
  "name": "tailscale_list_organization_tailnets",
  "arguments": {"organization": "-", "limit": 25, "cursor": "<returned-cursor>"}
}
```

Listing is read-only and idempotent, but can expose sensitive organization-wide inventory. A failed page returns an error, not a partial collection or fabricated continuation.

#### Creating An API-Only Tailnet

```json
{
  "name": "tailscale_create_organization_tailnet",
  "arguments": {
    "organization": "-",
    "body": {"displayName": "Example API Tailnet"},
    "confirm": "createOrganizationTailnet"
  }
}
```

`body` is a required JSON object containing a nonblank string `displayName`. Upstream enforces naming and uniqueness rules. This creates an **API-only tailnet**: it has no human users, does not appear in the admin console, and is managed entirely through the API. Creation does not switch the MCP server's configured target. The full success response is preserved, including `id`, `displayName`, `orgId`, `dnsName`, `createdAt`, `oauthClient`, and `alreadyExists`.

**Treat the result as a secret.** `oauthClient.secret` is a sensitive one-time credential returned to the authorized caller. Store it securely when returned; do not assume it can be retrieved later, and do not discard credentials merely because `alreadyExists` is present. Review MCP client transcripts, model context, tracing, and retention policies before granting creation. The server does not log this secret or include it in failure payloads. Creation is neither read-only nor idempotent; the server does not automatically retry it. An ambiguous failure does not prove that creation did not happen. Check authoritative state before deciding whether to submit another confirmed call.

#### Deleting Only The Configured Tailnet

**Deletion is irreversible and removes all users, devices, and configuration.** The following is an illustrative `tools/call` payload, not a setup or verification step. It is accepted only if `TAILSCALE_TAILNET` is explicitly configured as exactly `example.com` and the configured credential has authority to delete that target:

```json
{
  "name": "tailscale_delete_tailnet",
  "arguments": {"tailnet": "example.com", "confirm": "deleteTailnet"}
}
```

The `tailnet` argument is an acknowledgement, not a target override: it must exactly equal the configured value, without alias resolution or normalization. Missing, blank, non-string, `-`, and mismatched targets are rejected, as are blank or `-` configured targets. Correct confirmation alone cannot bypass this check. The server reuses the configured credential, sends a bodyless DELETE, and accepts an empty upstream 200 response. It does not exchange tokens, accept per-call credentials, infer the target from creation output, or support arbitrary cross-tailnet deletion. A credential/target mismatch remains an upstream error. Deletion is marked destructive and idempotent, but these advisory hints are not permission to automatically retry an ambiguous failure.

#### Lifecycle Grants

Use exact names in the capability's `tools` array for least privilege. For example, the following value inside a Tailscale grant's `app` object permits only organization listing:

```json
{
  "jaxxstorm.com/cap/mcp": [{
    "tools": ["tailscale_list_organization_tailnets"],
    "resources": []
  }]
}
```

Replace that exact tool name with `tailscale_create_organization_tailnet` or `tailscale_delete_tailnet` to authorize only the corresponding action. Coverage reports label these permissions `tool:<name>`; do **not** include the `tool:` prefix in capability arrays.

| Tool Selector | Lifecycle Access |
|---|---|
| `group:organizations:read` | Listing only |
| `group:organizations` | Listing, creation, and deletion |
| `read:*` | Listing, plus all other registered readers |
| `*` | All three, plus every other registered tool |
| `group:tailnet` | None of these lifecycle tools |

Existing wildcard selectors expand on upgrade: `*` now includes creation and deletion, and `read:*` now exposes organization listing. Review existing policies rather than assuming this feature is opt-in for wildcard users. Group grants still require confirmation for creation/deletion and the exact target acknowledgement for deletion. Upstream `all` scope alone authorizes no MCP calls. Discovery is caller-filtered, and ungranted direct calls are denied before upstream access. Inspect `--list-groups` offline to review the new group before upgrading.

### Curated Operator Tools

Curated tools are task-oriented wrappers around one or more generated endpoint tools. They do not replace the generated `tailscale_<operation>` tools and are not counted separately in OpenAPI coverage. Each curated tool uses its own grant name matching the tool name.

Status and ACL tools:

| Tool | Description | Required Grant |
|------|-------------|----------------|
| `tailscale_status` | Compose device/settings reads into a setup health response | `tailscale_status` |
| `tailscale_get_acl` | Read HuJSON ACL policy and ETag | `tailscale_get_acl` |
| `tailscale_validate_acl` | Validate HuJSON ACL text without applying it | `tailscale_validate_acl` |
| `tailscale_preview_acl` | Preview ACL rules for a user or IP:port | `tailscale_preview_acl` |
| `tailscale_update_acl` | Update HuJSON ACL policy with ETag and `confirm: "setPolicyFile"` | `tailscale_update_acl` |

Device workflow tools include `tailscale_list_devices`, `tailscale_get_device`, `tailscale_device_routes`, `tailscale_device_posture_attributes`, `tailscale_device_authorize`, `tailscale_device_deauthorize`, `tailscale_device_delete`, `tailscale_device_rename`, `tailscale_device_expire_key`, `tailscale_device_set_routes`, `tailscale_device_set_tags`, `tailscale_device_set_ip`, `tailscale_device_update_key`, `tailscale_device_set_posture_attribute`, `tailscale_device_delete_posture_attribute`, `tailscale_device_batch_update_posture_attributes`, and `tailscale_set_devices_authorized`.

Additional curated domain wrappers use `_curated` suffixes where a generated tool already owns the canonical OpenAPI operation name, for example `tailscale_get_dns_configuration_curated`, `tailscale_list_users_curated`, `tailscale_list_webhooks_curated`, and `tailscale_create_key_curated`.

Mutating curated tools require both the curated tool grant and an explicit `confirm` argument. Single-operation wrappers use the underlying OpenAPI operation ID as the confirmation token. Bulk/composed mutating workflows use the curated tool name as the confirmation token.

Local CLI diagnostics are disabled by default. Enable them only on hosts where the local `tailscale` binary is trusted and available:

```bash
export TAILSCALE_LOCAL_CLI=1
```

When enabled, the server registers `tailscale_local_status`, `tailscale_ping`, `tailscale_netcheck`, and `tailscale_local_version`. These tools execute the local `tailscale` binary without a shell, validate inputs, bound output size, use timeouts, and are marked read-only.

Common resources:

| URI | Description | Required Grant |
|-----|-------------|----------------|
| `bootstrap://status` | Health-check endpoint | `bootstrap://status` |
| `tailscale://devices` | Complete device list with metadata | `tailscale://devices` |
| `tailscale://policy` | Current Tailscale ACL policy file | `tailscale://policy` |
| `tailscale://tailnet-settings` | Tailnet configuration and settings | `tailscale://tailnet-settings` |
| `tailscale://device` | Individual device details | `tailscale://device` |
| `tailscale://dns/configuration` | Full DNS configuration | `tailscale://dns/configuration` |
| `tailscale://keys` | Active keys visible to the API token | `tailscale://keys` |
| `tailscale://user-invites` | Open user invites | `tailscale://user-invites` |
| `tailscale://webhooks` | Webhooks | `tailscale://webhooks` |
| `tailscale://services` | Services | `tailscale://services` |
| `tailscale://posture/integrations` | Posture integrations | `tailscale://posture/integrations` |
| `tailscale://oauth-apps` | OAuth apps | `tailscale://oauth-apps` |

## API Coverage

Full Tailscale API parity is tracked with repository tooling under `tools/coverage/`. The tooling maps each Tailscale OpenAPI operation to an MCP tool, resource, prompt workflow, or reviewed exclusion, then writes generated reports under `coverage/`.

Refresh the vendored Tailscale OpenAPI snapshot with:

```bash
make openapi-refresh
```

Run coverage generation with:

```bash
make coverage
```

Review `coverage/mcp-coverage.md` for current MCP coverage and `coverage/parity-backlog.md` for unimplemented API operations.

Aperture uses a separate cached contract at `tools/aperture/openapi.json`, with provenance and SHA-256 in `tools/aperture/snapshot-metadata.yaml`. Routine build/test/coverage targets, startup, and tool registration do not fetch its live schema. Refresh only intentionally, while connected to the tailnet, with `make aperture-openapi-refresh`; review the snapshot, metadata, and five-operation mapping together. See [offline contract and refresh](aperture.md#offline-contract-and-refresh). The Tailscale refresh command and generated coverage reports remain separate and unchanged.

## Example Queries

```text
Use get_device_info to get details about device "100.101.102.103"
```

```text
List all devices in my tailnet using list_all_devices
```

```text
Show me the current Tailscale policy by reading the tailscale://policy resource
```

## Logging

Enable debug logging to see detailed protocol exchanges and OAuth grants:

```bash
./ts-mcp --debug
```

Debug mode includes MCP message flow, OAuth grants parsing, user authentication context, and access control decisions.

## Troubleshooting

### Upgrade And Rollback

Before upgrading, migrate implicit resource prefixes, explicitly opt into loopback only where required, and compare `--list-groups` output with local CLI on and off. Keep exact grants where upgrade-driven permission expansion is unacceptable. TLS and file-backed federation can be enabled independently.

For the Aperture release:

1. Aperture is disabled by default. Before enabling it, audit existing `*` and `read:*` grants, including `TS_MCP_LOCAL_GRANTS`; they match Aperture tools only when enabled in HTTP mode. Use reviewed exact names or service groups if that expansion is unwanted. Compare `--list-groups --aperture=false` with `--list-groups --aperture` offline.
2. If using Aperture, grant the MCP tsnet node only its intended upstream roles: admin for configuration and explicit `read_pricing: true` for pricing. Enable with `--aperture` or `TS_MCP_APERTURE=true` and set `APERTURE_URL` if the upstream is not `http://ai/aperture`; the URL alone does not enable it. `--aperture=false` overrides the environment opt-in. Keep the existing Tailscale startup credentials and tags.
3. Keep Tailscale enabled (the default) to preserve existing `/mcp` clients. Prefer `/tailscale/mcp` for new configurations; both paths use the same Tailscale handler, server, and session state without redirects, with identical grants and protections on tailnet and enabled loopback. Add a separate `/aperture/mcp` entry on the same host/port only when Aperture is enabled. For Aperture-only deployment, use `--tailscale=false --aperture` and remove Tailscale client entries; neither Tailscale route remains available. Existing Tailscale names, grants, resources, prompts, and mutation safeguards are unchanged when enabled.
4. Verify route isolation and authorization offline. An optional non-mutating tailnet smoke test requires the node's upstream roles and the caller's MCP grants; do not perform live configuration replacement without explicit operator approval and a prepared full replacement.
5. To roll back to a binary that supports only `/mcp`, deploy it and change Tailscale clients using `/tailscale/mcp` to `/mcp`; existing `/mcp` clients need no URL change. Remove Aperture client entries and unsupported service options, and review grants for the older binary. An Aperture-only deployment must restore the older binary's required `TAILSCALE_TAILNET` and Admin API startup read access; older binaries cannot preserve Aperture-only serving. MCP binary rollback does not revert upstream Aperture configuration writes; inspect authoritative state before any deliberate recovery write.

Older binaries may not understand the new flags, environment variables, `idTokenFile`, or tool selectors. Before rollback, remove unsupported options and translate selectors into reviewed exact grants; arrange a supported credential source rather than exposing token contents. Reverting can restore unsafe implicit resource-prefix authorization and unconditional loopback behavior, so prefer a forward fix and isolate an older deployment if rollback is unavoidable. No persisted-state migration is introduced; protect existing operator-owned state and never substitute fork-bundled state.

**"No MCP capabilities found"**

* Verify your ACL policy includes the correct grants configuration
* Check that the server node has the appropriate tags
* Ensure the user has been granted access to MCP capabilities

**"Access denied: insufficient permissions"**

* Review the grants configuration in your ACL policy
* Verify the user is listed in the `src` field of the relevant grant
* Check that the requested tool/resource is included in the capability definition

**"Failed to get Tailscale status"**

* Ensure Tailscale is running and authenticated
* Verify `TAILSCALE_OAUTH_TOKEN` can authenticate tsnet startup
* Check network connectivity to Tailscale coordination servers

**"Tailscale credential validation failed"**

* Verify `TAILSCALE_OAUTH_TOKEN` is set and valid JSON when using a JSON credential
* Verify the credential can read tailnet settings for `TAILSCALE_TAILNET`
* Add the missing OAuth scopes or federated credential permissions reported by Tailscale

**tsnet authentication fails during startup**

* OAuth credentials must include a usable `clientSecret`
* Federated credentials must include `clientId` and exactly one of `idToken` or `idTokenFile`; verify file access and atomic rotation without printing its contents
* In tailnet HTTP mode, OAuth and federated credentials must set `TS_ADVERTISE_TAGS`, for example `tag:mcp-server`; stdio does not require tags
* Raw bearer tokens must be auth-key-like if they are expected to enroll the tsnet node
