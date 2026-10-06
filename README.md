# Tailscale MCP Server

An MCP (Model Context Protocol) server for Tailscale and Aperture, enabling detailed Tailscale queries and operations plus Aperture configuration and pricing management. It serves independent Streamable HTTP endpoints at `/tailscale/mcp` and `/aperture/mcp` on shared ports and uses Tailscale grants for fine-grained access control.

## Features

* **Streamable HTTP Transport**: Serves `/tailscale/mcp` and `/aperture/mcp` on the same listener and port via Tailscale, with optional HTTPS and separately opt-in loopback HTTP
* **Comprehensive Tailscale Integration**: Full mapped coverage of the vendored Tailscale OpenAPI snapshot
* **Aperture Integration**: Five typed configuration and pricing tools, with explicit confirmation and ETag protection for configuration replacement
* **Alpha Organization APIs**: List organization tailnets, create API-only tailnets, and delete only the explicitly configured tailnet with guarded tools
* **OAuth Grants Authorization**: Fine-grained MCP access control with `jaxxstorm.com/cap/mcp`
* **Single Credential Startup**: Uses `TAILSCALE_OAUTH_TOKEN` for Admin API access and tsnet startup
* **Configurable tsnet State**: Stores tsnet state on the filesystem by default, with optional Kubernetes Secret or AWS SSM state stores
* **Legacy stdio Compatibility**: Deprecated Tailscale-only stdio mode remains available for older local clients; Aperture requires HTTP

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

The default endpoints are `http://<hostname>.yourtailnet.ts.net:8080/tailscale/mcp` and `http://<hostname>.yourtailnet.ts.net:8080/aperture/mcp`; no loopback listener opens by default. Use `--tls` for tailnet HTTPS (default port 443 for both paths, requiring tailnet HTTPS support). Certificate issuance can publish the node's DNS name in certificate transparency logs.

**Compatible Tailscale endpoints:** `/tailscale/mcp` is the preferred explicit route. Existing clients using `/mcp` continue to work without a redirect: both paths use the same Tailscale handler, server, catalog, and session state, with identical grants and transport protections on tailnet and enabled loopback listeners. Aperture remains a separate server at `/aperture/mcp` on the same host and port. When rolling back to a binary that supports only `/mcp`, change only clients using the explicit route and remove Aperture entries. Binary rollback does not undo upstream configuration writes. See [upgrade and rollback guidance](docs/usage.md#upgrade-and-rollback).

Startup credentials are unchanged, even if you only use Aperture. `--aperture-url` / `APERTURE_URL` defaults to `http://ai/aperture`. Aperture sees the MCP tsnet node, not the original caller: grant that node upstream admin for configuration and explicit `read_pricing: true` for pricing (admin alone is insufficient). MCP caller grants remain independently required. No new API key is needed and no Admin API credentials are forwarded to Aperture.

**Audit wildcard grants before upgrading:** `*` includes all five Aperture tools, including destructive configuration replacement; `read:*` includes config reads, non-mutating validation, and both pricing tools. Existing exact Tailscale permissions and Tailscale groups do not grant Aperture access. See [Aperture tools and safeguards](docs/aperture.md).

Local HTTP requires both `--local-http` and explicit grants, for example:

```bash
./ts-mcp --local-http --local-grants '{"tools":["list_all_devices"],"resources":[]}'
```

This additionally opens `http://127.0.0.1:8080/tailscale/mcp` and `http://127.0.0.1:8080/aperture/mcp`; the example grant permits only the Tailscale device-list tool. Every process able to connect receives those grants; avoid enabling it on untrusted shared hosts. `--local-port` is independent of the tailnet `--port`. Deprecated stdio uses `--stdio --local-grants` for Tailscale only, without starting tsnet, initializing Aperture, or requiring advertised tags, but still validates Admin API credentials. See the usage guide for migration, limits, and least-privilege selectors.

Organization lifecycle tools are Alpha: `tailscale_list_organization_tailnets`, `tailscale_create_organization_tailnet`, and `tailscale_delete_tailnet`. Creation returns sensitive one-time OAuth credentials; deletion is irreversible and requires an exact configured-target acknowledgement plus confirmation. Existing `*` tool grants now include these mutations, while `read:*` includes organization listing. Review [lifecycle examples, grants, scopes, and startup limitations](docs/usage.md#alpha-organization-lifecycle) before enabling them. No new resources or prompts are added.

## Documentation

* [Usage Guide](docs/usage.md): installation, configuration, credentials, grants, client setup, tools, resources, coverage, and troubleshooting
* [Aperture Guide](docs/aperture.md): tools, upstream identity, grants, safe replacement, pricing, and offline schema maintenance
* [Coverage Report](coverage/mcp-coverage.md): generated Tailscale OpenAPI to MCP coverage mapping
* [Parity Backlog](coverage/parity-backlog.md): generated list of unmapped API operations
* [Integration Attribution](docs/integration.md): reviewed fork source and integration boundaries

## Development

```bash
go test ./...
go build ./...
make coverage
```

Routine builds, tests, coverage, startup, and tool registration do not fetch the live Aperture schema. They use `tools/aperture/openapi.json` and its provenance/checksum metadata. Only an intentional `make aperture-openapi-refresh` while connected to the tailnet refreshes that contract; review the snapshot, metadata, and operation mappings together. See [schema maintenance](docs/aperture.md#offline-contract-and-refresh).

## Useful Links

* [Tailscale API Documentation](https://tailscale.com/kb/1101/api/)
* [Tailscale OAuth Grants](https://tailscale.com/kb/1017/grant-access-to-apps/)
* [MCP Protocol Documentation](https://modelcontextprotocol.io/)
