## 1. Credential Model

- [x] 1.1 Inspect current Tailscale Go client and tsnet APIs to confirm how OAuth or federated credentials can authenticate Admin API requests and tsnet node startup.
- [x] 1.2 Add a credential configuration type with a single required environment variable for OAuth or federated credentials.
- [x] 1.3 Remove `TAILSCALE_API_KEY` as a required CLI field and remove `TS_AUTH_KEY` from the primary startup path.
- [x] 1.4 Add safe credential classification for OAuth-backed, federated, and unknown credentials without logging secret material.

## 2. Client Wiring

- [x] 2.1 Configure the typed Tailscale Admin API client from the single credential.
- [x] 2.2 Configure the generic Admin API client in `internal/readapi` from the single credential.
- [x] 2.3 Configure tsnet authentication from the same credential when supported, with explicit startup errors when unsupported or invalid.
- [x] 2.4 Ensure incoming MCP `jaxxstorm.com/cap/mcp` grant enforcement remains unchanged.

## 3. Startup Validation

- [x] 3.1 Add low-risk Admin API validation for the supplied credential and tailnet before serving MCP.
- [x] 3.2 Return actionable startup errors for missing credentials, invalid credentials, missing scopes, and tailnet access failures.
- [x] 3.3 Add tests for missing credential handling, classification, and validation error formatting.

## 4. Documentation

- [x] 4.1 Update docs required environment variables to use the single OAuth or federated credential.
- [x] 4.2 Update docs install/run examples and Claude or Streamable HTTP integration snippets to remove dual-credential setup.
- [x] 4.3 Document required OAuth scopes or federated credential permissions for full OpenAPI coverage.
- [x] 4.4 Update troubleshooting for invalid credentials, missing scopes, and tsnet authentication failures.

## 5. Verification

- [x] 5.1 Run `go test ./...`.
- [x] 5.2 Run `go build ./...`.
- [x] 5.3 Run `make coverage` and verify coverage remains 90/90 with no gaps introduced.
- [x] 5.4 Run `openspec status --change "use-single-oauth-credential"` and confirm artifacts are complete.
