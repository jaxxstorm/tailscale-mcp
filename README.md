# Tailscale MCP Server

An MCP (Model Context Protocol) server for Tailscale, enabling detailed queries and operations for devices, DNS, users, invites, keys, webhooks, services, logging, policy validation, and tailnet settings. It serves MCP over Streamable HTTP on `/mcp` and uses Tailscale OAuth grants for fine-grained access control.

## Features

* **Streamable HTTP Transport**: Serves MCP on `/mcp` via Tailscale and localhost
* **Comprehensive Tailscale Integration**: Full mapped coverage of the vendored Tailscale OpenAPI snapshot
* **OAuth Grants Authorization**: Fine-grained MCP access control with `jaxxstorm.com/cap/mcp`
* **Single Credential Startup**: Uses `TAILSCALE_OAUTH_TOKEN` for Admin API access and tsnet startup
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

The server exposes MCP at:

* `http://<hostname>.yourtailnet.ts.net:8080/mcp`
* `http://127.0.0.1:8080/mcp`

## Documentation

* [Usage Guide](docs/usage.md): installation, configuration, credentials, grants, client setup, tools, resources, coverage, and troubleshooting
* [Coverage Report](coverage/mcp-coverage.md): generated Tailscale OpenAPI to MCP coverage mapping
* [Parity Backlog](coverage/parity-backlog.md): generated list of unmapped API operations

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
