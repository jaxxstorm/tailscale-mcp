# Tailscale MCP Server

An MCP (Model Context Protocol) server for Tailscale, enabling detailed queries and operations for devices, DNS, users, invites, keys, webhooks, services, logging, policy validation, and tailnet settings. It serves MCP over Streamable HTTP on `/mcp` and uses Tailscale OAuth grants for fine-grained access control.

## Features

* **Streamable HTTP Transport**: Serves MCP on `/mcp` via Tailscale, with optional HTTPS and separately opt-in loopback HTTP
* **Comprehensive Tailscale Integration**: Full mapped coverage of the vendored Tailscale OpenAPI snapshot
* **OAuth Grants Authorization**: Fine-grained MCP access control with `jaxxstorm.com/cap/mcp`
* **Single Credential Startup**: Uses `TAILSCALE_OAUTH_TOKEN` for Admin API access and tsnet startup
* **Configurable tsnet State**: Stores tsnet state on the filesystem by default, with optional Kubernetes Secret or AWS SSM state stores
* **Legacy stdio Compatibility**: Deprecated stdio mode remains available for older local clients

## Quick Start

```bash
export TAILSCALE_OAUTH_TOKEN='{"type":"oauth","clientId":"k123...","clientSecret":"tskey-client-...","scopes":["all"]}'
export TAILSCALE_TAILNET="yourtailnet.com"
export TS_ADVERTISE_TAGS="tag:mcp-server"
./ts-mcp
```

You can also provide the OAuth client ID separately:

```bash
export TAILSCALE_OAUTH_TOKEN="tskey-client-..."
export TAILSCALE_OAUTH_CLIENT_ID="k123..."
export TAILSCALE_TAILNET="yourtailnet.com"
export TS_ADVERTISE_TAGS="tag:mcp-server"
./ts-mcp
```

The default endpoint is `http://<hostname>.yourtailnet.ts.net:8080/mcp`; no loopback listener opens by default. Use `--tls` for tailnet HTTPS (default port 443, requiring tailnet HTTPS support). Certificate issuance can publish the node's DNS name in certificate transparency logs.

Local HTTP requires both `--local-http` and explicit grants, for example:

```bash
./ts-mcp --local-http --local-grants '{"tools":["list_all_devices"],"resources":[]}'
```

This additionally opens `http://127.0.0.1:8080/mcp`. Every process able to connect receives those grants; avoid enabling it on untrusted shared hosts. `--local-port` is independent of the tailnet `--port`. Deprecated stdio uses `--stdio --local-grants` without starting tsnet or requiring advertised tags, but still validates Admin API credentials. See the usage guide for migration, limits, and least-privilege selectors.

## Documentation

* [Usage Guide](docs/usage.md): installation, configuration, credentials, grants, client setup, tools, resources, coverage, and troubleshooting
* [Coverage Report](coverage/mcp-coverage.md): generated Tailscale OpenAPI to MCP coverage mapping
* [Parity Backlog](coverage/parity-backlog.md): generated list of unmapped API operations
* [Integration Attribution](docs/integration.md): reviewed fork source and integration boundaries

## Development

```bash
go test ./...
go build ./...
make coverage
```

## Useful Links

* [Tailscale API Documentation](https://tailscale.com/kb/1101/api/)
* [Tailscale OAuth Grants](https://tailscale.com/kb/1017/grant-access-to-apps/)
* [MCP Protocol Documentation](https://modelcontextprotocol.io/)
