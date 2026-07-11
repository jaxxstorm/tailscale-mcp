## 1. tsnet Startup State

- [x] 1.1 Add a small helper that derives a deterministic tsnet state directory from the configured hostname.
- [x] 1.2 Configure `tsnet.Server.Dir` during Streamable HTTP startup using the derived state directory.
- [x] 1.3 Preserve existing `Hostname`, `AdvertiseTags`, credential configuration, and `TSNET_FORCE_LOGIN` behavior.

## 2. Build Metadata Registration

- [x] 2.1 Identify and use the Tailscale build info registration API appropriate for the current dependency version.
- [x] 2.2 Register build information using the existing MCP server name/version before `tsServer.Listen` serves tailnet requests.
- [x] 2.3 Ensure stdio mode remains unaffected and does not require tsnet build metadata setup.

## 3. Verification

- [x] 3.1 Add or update tests for hostname-derived state directory behavior, including default and custom hostnames.
- [x] 3.2 Add or update tests that verify tsnet server configuration keeps credential and advertised tag behavior intact.
- [x] 3.3 Run `go test ./...` and fix any regressions.
- [x] 3.4 Confirm no MCP tool/resource names, grant permissions, or OpenAPI coverage mappings changed.
