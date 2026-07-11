## 1. Logger Adapter

- [x] 1.1 Add a small helper that adapts printf-style tsnet log messages to the existing Zap logger with a stable `component=tsnet` field.
- [x] 1.2 Ensure the helper handles formatted messages without writing to the standard library logger.

## 2. tsnet Server Configuration

- [x] 2.1 Configure `tsnet.Server.UserLogf` to use the application logger for normal tsnet startup and lifecycle messages.
- [x] 2.2 Configure `tsnet.Server.Logf` only when debug logging is enabled, routing verbose backend logs through the application logger at debug level.
- [x] 2.3 Preserve existing tsnet state directory, hostname, advertised tags, credential, force-login, build metadata, Streamable HTTP, localhost, and stdio behavior.

## 3. Verification

- [x] 3.1 Add or update tests for the tsnet logger adapter output and fields.
- [x] 3.2 Add or update tests for tsnet server logging configuration in debug and non-debug modes.
- [x] 3.3 Run `go test ./...` and fix any regressions.
- [x] 3.4 Confirm no MCP tool/resource names, grant permissions, or OpenAPI coverage mappings changed.
