# Usage Guide

## Prerequisites

* [Tailscale](https://tailscale.com) account with an OAuth or federated credential
* Go 1.26.4 or higher if building from source

## Installation

Download the latest pre-built binary for your platform from the release page, or build from source:

```bash
git clone <repo_url>
cd <repo_dir>
go mod tidy
go build -o ts-mcp .
```

You can also install with Homebrew:

```bash
brew install jaxxstorm/tap/ts-mcp
```

## Configuration

Required environment variables:

```bash
export TAILSCALE_OAUTH_TOKEN='{"type":"oauth","clientId":"k123...","clientSecret":"tskey-client-...","scopes":["all"]}'
export TAILSCALE_TAILNET="yourtailnet.com"
export TS_ADVERTISE_TAGS="tag:mcp-server"
```

Optional environment variables:

```bash
export TS_HOSTNAME="ts-mcp"
export TS_PORT="8080"
```

`TS_ADVERTISE_TAGS` is required when `TAILSCALE_OAUTH_TOKEN` is an OAuth client secret or federated credential because tsnet mints a tagged node auth key during startup. The OAuth client or federated credential must be allowed to create auth keys for the advertised tag.

Command line options:

* `--debug` / `-d`: Enable debug logging
* `--version` / `-v`: Show version information
* `--oauth-client-id`: OAuth client ID to use when `TAILSCALE_OAUTH_TOKEN` is a raw `tskey-client-*` secret
* `--advertise-tags`: Comma-separated Tailscale tags to advertise when minting tsnet auth keys from OAuth or federated credentials
* `--stdio`: Use deprecated stdio compatibility mode instead of Streamable HTTP

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

Resource grants:

* `bootstrap://status`: Health check endpoint
* `tailscale://devices`: Device list resource
* `tailscale://policy`: Policy file access
* `tailscale://tailnet-settings`: Tailnet settings access
* `tailscale://device`: Individual device resource access
* `tailscale://dns/*`, `tailscale://keys`, `tailscale://webhooks`, `tailscale://services`, `tailscale://oauth-apps`, and similar read API resources
* `*`: Allow all resources

## Running The Server

Streamable HTTP is the default transport:

```bash
./ts-mcp
```

The server exposes MCP at:

* `http://<hostname>.yourtailnet.ts.net:8080/mcp`
* `http://127.0.0.1:8080/mcp`

Deprecated stdio compatibility mode is available for older local clients that cannot use Streamable HTTP yet:

```bash
./ts-mcp --stdio
```

## Claude Desktop Integration

Use Claude Desktop's Streamable HTTP remote MCP configuration when available. Point it at the Tailscale or localhost `/mcp` endpoint.

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
        "TS_ADVERTISE_TAGS": "tag:mcp-server"
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
* Federated credentials must include `clientId` and `idToken`
* OAuth and federated credentials must set `TS_ADVERTISE_TAGS`, for example `tag:mcp-server`
* Raw bearer tokens must be auth-key-like if they are expected to enroll the tsnet node
