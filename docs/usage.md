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

Required environment variables for tailnet HTTP with OAuth credentials:

```bash
export TAILSCALE_OAUTH_TOKEN='{"type":"oauth","clientId":"k123...","clientSecret":"tskey-client-...","scopes":["all"]}'
export TAILSCALE_TAILNET="yourtailnet.com"
export TS_ADVERTISE_TAGS="tag:mcp-server"
```

Optional environment variables:

```bash
export TS_HOSTNAME="ts-mcp"
export TSNET_STATE="file://"
```

Leave `TS_PORT` unset to use the TLS-dependent default; setting it explicitly overrides that default, just like `--port`.

`TS_ADVERTISE_TAGS` is required for tailnet HTTP when `TAILSCALE_OAUTH_TOKEN` is an OAuth client secret or federated credential because tsnet mints a tagged node auth key during startup. The OAuth client or federated credential must be allowed to create auth keys for the advertised tag. Stdio never starts tsnet or requires advertised tags, but still requires the tailnet and Admin API credentials and validates their access before serving.

Command line options:

* `--debug` / `-d`: Enable debug logging
* `--version` / `-v`: Show version information offline, without credentials or network initialization
* `--list-groups`: Print deterministic tool names, groups, and read-only classification for the configured registered surface, then exit offline without credentials or a tailnet
* `--oauth-client-id`: OAuth client ID to use when `TAILSCALE_OAUTH_TOKEN` is a raw `tskey-client-*` secret
* `--advertise-tags`: Comma-separated Tailscale tags to advertise when minting tsnet auth keys from OAuth or federated credentials
* `--state`: tsnet state location. Same as `TSNET_STATE`
* `--stdio`: Use deprecated stdio compatibility mode instead of Streamable HTTP
* `--local-grants` / `TS_MCP_LOCAL_GRANTS`: A single JSON object with `tools` and `resources` arrays of strings; unset or empty grants authorize nothing
* `--local-http` / `TS_MCP_LOCAL_HTTP`: Enable additional loopback HTTP, default `false`; requires HTTP mode and an explicit non-empty local grant
* `--local-port` / `TS_MCP_LOCAL_PORT`: Loopback port, default `8080`, independent of tailnet TLS and port
* `--tls` / `TS_TLS`: Enable tailnet HTTPS, default `false`; does not enable TLS on loopback
* `--port` / `TS_PORT`: Tailnet port; defaults to `443` with TLS or `8080` without TLS unless explicitly set

Ports must be integers from 1 through 65535. Invalid ports, malformed local JSON, unknown fields, invalid field types, and contradictory listener options fail startup. Local grants are not a capability-key wrapper or an array of entries: use `{"tools":["list_all_devices"],"resources":[]}`. Configuring grants alone never opens loopback, and local grants never authorize tailnet callers.

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

Create a Tailscale OAuth client or federated credential that can read tailnet settings at startup and perform every Admin API operation you expose through MCP.

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

Federated JSON requires `clientId` and exactly one of `idToken` or `idTokenFile`; both or neither are errors. An external identity-provider refresher must acquire tokens and atomically replace the file: write a complete new token to a restricted temporary file in the same directory, then rename it over the configured path. Do not truncate/rewrite the live file. Restrict ownership and permissions on both file (for example `0600`) and parent directory (for example `0700`) to the server/refresher identities, including during replacement. Never log tokens or place them in the repository, image, or release archive.

Both typed and generic Admin API clients reread and trim the file whenever federation needs a new assertion. A cached valid access token may be reused, so this is not a reread on every API request. Missing, unreadable, or empty files fail authentication without falling back to a stale assertion. Existing inline, OAuth, and bearer credential forms remain supported.

tsnet uses a startup snapshot of the assertion; file rotation refreshes Admin API assertions, not continuous tsnet reauthentication, and does not obtain OIDC tokens automatically. Failure to obtain the startup snapshot is fatal. All serving modes, including stdio, validate Admin API access with the existing low-risk tailnet-settings read under a 30-second deadline before serving; retain permission for that read even when exposing only narrow tool grants. This is a credential-validation deadline, not a guarantee that all tsnet startup completes within 30 seconds.

For full OpenAPI coverage, grant the credential scopes or permissions for devices, DNS, policy files, tailnet settings, users, invites, keys, webhooks, services, logging, OAuth apps, and posture integrations. Mutating MCP tools also require the operation-specific `confirm` argument and matching Tailscale API write permissions.

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
* `*`: Allow all tools
* `read:*`: Allow all registered tools classified as read-only by server metadata
* `group:<name>`: Allow registered readers and writers in that group, for example `group:dns`
* `group:<name>:read`: Allow only registered readers in that group, for example `group:dns:read`

Tool selectors have **OR semantics**, not intersection: `["read:*", "group:dns"]` permits every registered reader plus DNS writers. Unknown groups and unsupported selectors match nothing; arbitrary glob syntax is not supported. Read-only classification comes from trusted registration metadata, not the tool name. Authorized mutations still require their existing confirmation tokens and Admin API write permissions.

Read-only is not non-sensitive: readers can expose policy, device/user information, logs, or key material visible to the server credential. Global, read, and group selectors can broaden permissions when matching tools are added on upgrade. Prefer exact tool names for tightly controlled deployments and review catalog changes before upgrading.

Tool and group names are stable permission identities. Inspect the actual configured surface without credentials or network access:

```bash
./ts-mcp --list-groups
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

By default only `http://<hostname>.yourtailnet.ts.net:8080/mcp` is exposed. To enable tailnet HTTPS:

```bash
./ts-mcp --tls
```

Enable MagicDNS and HTTPS certificates in the tailnet and use the node's fully qualified `*.ts.net` name. Tailscale-issued certificates can publish that DNS name in public certificate transparency logs; choose the hostname accordingly. TLS listener/certificate failures never fall back to plaintext. The default HTTPS URL is `https://<hostname>.yourtailnet.ts.net:443/mcp`; `--tls --port 8443` explicitly changes it to port 8443. Use the full endpoint URL logged at startup.

Tailnet HTTP Host checks accept only the ready node's full/short DNS name or Tailscale IPs at the configured port. Arbitrary DNS aliases and reverse-proxy Host overrides are rejected, even with a matching Origin. For HTTPS, use the fully qualified certificate name. Forwarded headers do not establish the expected hostname, scheme, or caller identity.

Tailnet readiness and listener acquisition observe shutdown cancellation. The SDK's initial `tsnet.Start()` call does not accept a context and cannot safely be interrupted by closing the partially initialized server; cancellation during that phase is handled after initialization returns. The Admin API validation deadline is not an overall tsnet startup deadline.

To additionally enable loopback with narrow permissions:

```bash
./ts-mcp --tls --local-http --local-port 8081 \
  --local-grants '{"tools":["list_all_devices"],"resources":["bootstrap://status"]}'
```

This leaves tailnet HTTPS on port 443 and adds plain HTTP at `http://127.0.0.1:8081/mcp`. Without `--local-port`, loopback uses 8080 even with TLS. Loopback binds only `127.0.0.1`, but **every process able to connect receives the same local grants**. This is not same-user authentication or a multi-user service. Avoid it on untrusted shared hosts and do not proxy or forward it to other users. Host/DNS-rebinding and Origin checks do not authenticate local processes.

When present, Origin must be a single HTTP(S) origin matching the listener's scheme, hostname, and effective port. Lookalike hosts, `null`, paths, queries, fragments, and multiple origins are rejected. Forwarded headers do not override identity or scheme. Non-browser clients may omit Origin, but still undergo Host and grant checks.

Deprecated stdio compatibility mode is available for older local clients that cannot use Streamable HTTP yet:

```bash
./ts-mcp --stdio --local-grants '{"tools":["list_all_devices"],"resources":[]}'
```

Stdio opens no HTTP listeners and never initializes tsnet or requires advertised tags. It still validates Admin API credentials and denies protected operations without local grants. Do not combine stdio with local HTTP opt-in.

### Limits And Shutdown

HTTP POST bodies are limited to **4 MiB**, including chunked bodies and requests from peers without MCP grants. Header reads have a **10-second** timeout, body reads a **30-second** deadline, and idle keep-alive connections a **120-second** timeout. Oversized or slow bodies fail before operation dispatch; account for JSON encoding overhead when submitting large ACL policies. The body deadline is cleared after consumption and is not a tool-execution or SSE-stream deadline.

SIGINT/SIGTERM stops both listeners, cancels request/stream contexts, and drains within one shared **10-second** shutdown budget before force-closing remaining connections and cleaning up tsnet. Unexpected serving failures exit nonzero after cleanup. An interrupted mutation has an **ambiguous outcome**: cancellation is not rollback, and the upstream operation may already have applied. Do not automatically retry. Inspect authoritative state, ETags, and available audit records before deciding whether another confirmed write is needed.

## Claude Desktop Integration

Use Claude Desktop's Streamable HTTP remote MCP configuration when available. Point it at the tailnet `/mcp` endpoint, or loopback only after explicitly enabling local HTTP with narrow grants.

For older Claude Desktop versions that only support local stdio MCP servers, use the deprecated compatibility mode temporarily:

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
