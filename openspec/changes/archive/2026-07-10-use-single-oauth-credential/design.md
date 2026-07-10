## Context

The current CLI requires `TAILSCALE_API_KEY` for Admin API calls and accepts `TS_AUTH_KEY` for tsnet node authentication. That creates a two-secret deployment model: one credential for the MCP server's Tailscale network identity and another for API authorization. The project now exposes broad Tailscale OpenAPI coverage, so operators need an easier and more auditable way to provide least-privilege credentials.

Tailscale supports OAuth clients and federated credentials for scoped API access. This change moves startup to a single credential that can be used for Admin API requests and, where supported by tsnet/Tailscale auth key semantics, node authentication. The implementation must make credential expectations explicit and fail early when the provided credential cannot satisfy startup or Admin API requirements.

## Goals / Non-Goals

**Goals:**

- Replace the required dual-secret startup model with one required credential value.
- Support OAuth-client-backed credentials and federated credentials as the intended credential types.
- Use the same credential for all Tailscale Admin API clients, including the typed client and generic read API client.
- Use the same credential for tsnet authentication when the credential can authenticate the node, and report actionable errors otherwise.
- Add startup validation and credential classification that avoids logging secret material.
- Update docs, examples, and troubleshooting to describe the single-credential model and required scopes.
- Preserve all MCP tool/resource names, grant permissions, mutating confirmations, OpenAPI coverage, and transport behavior.

**Non-Goals:**

- Changing `jaxxstorm.com/cap/mcp` authorization semantics for incoming MCP users.
- Changing which OpenAPI endpoints are exposed or how mutating tools are confirmed.
- Implementing an interactive OAuth browser flow.
- Storing or refreshing credentials outside the supplied runtime environment.
- Guaranteeing every OAuth/federated credential can authenticate a tsnet node if Tailscale runtime support does not allow that token form.

## Decisions

### Decision: Introduce a single credential configuration field

The CLI will use one required environment-backed field, tentatively `TAILSCALE_OAUTH_TOKEN`, to configure both Admin API clients and tsnet authentication. Existing `TAILSCALE_API_KEY` and `TS_AUTH_KEY` should no longer be required or documented as the primary path.

Alternative considered: keep `TAILSCALE_API_KEY` and reinterpret it as a generic token. That preserves compatibility but hides the behavioral change and keeps API-key terminology in the operator surface.

### Decision: Keep credential handling opaque but classify for diagnostics

The implementation should avoid parsing token internals for security-sensitive decisions. It can classify credentials by safe prefixes or validation calls when available, but authorization truth comes from Tailscale responses. Startup diagnostics should say whether the token appears OAuth-backed, federated, or unknown without printing the token.

Alternative considered: decode token contents locally. That risks coupling to Tailscale token formats and leaking implementation assumptions.

### Decision: Validate with low-risk Admin API calls

Startup validation should use a low-risk read call such as fetching tailnet settings or another existing read endpoint to verify the credential and tailnet pairing. Missing scopes should produce clear startup guidance rather than failing later on the first MCP tool invocation.

Alternative considered: skip validation and let every tool fail independently. That makes deployment errors harder to diagnose.

### Decision: Preserve tsnet startup behavior as much as possible

The single credential will be assigned to tsnet authentication input where supported. If tsnet cannot authenticate with that credential, the server should fail with an explicit message describing the expected credential type and required Tailscale setup.

Alternative considered: keep a separate `TS_AUTH_KEY` fallback. That violates the one-credential goal and leaves operators with two secrets.

### Decision: Do not change MCP authorization or coverage

The supplied credential authorizes upstream Tailscale API calls. Incoming MCP access remains controlled by Tailscale grants via `jaxxstorm.com/cap/mcp`. Coverage metadata remains tied to OpenAPI operation mapping and must stay 90/90.

Alternative considered: derive MCP grants from OAuth scopes. That would mix upstream API authorization with per-user MCP authorization and weaken existing access controls.

## Risks / Trade-offs

- OAuth/federated token cannot authenticate tsnet node -> Fail early with a specific error and documentation for required credential setup.
- Startup validation requires broad enough read scope -> Document minimum validation scope and allow validation to report missing scope clearly.
- Breaking environment variable change disrupts deployments -> Mark as breaking, update README examples, and remove old variables from required configuration.
- Token classification could be inaccurate -> Treat classification as diagnostic only; rely on Tailscale API/runtime responses for correctness.
- Full OpenAPI coverage could regress during client refactor -> Run `go test ./...`, `go build ./...`, and `make coverage` to verify 90/90 remains unchanged.

## Migration Plan

1. Add a credential configuration type and replace `TAILSCALE_API_KEY`/`TS_AUTH_KEY` usage with one required OAuth/federated credential env var.
2. Wire the single credential into the typed Tailscale Admin API client and generic read API client.
3. Wire the same credential into tsnet authentication and improve startup errors if authentication fails.
4. Add startup validation and safe credential classification logs.
5. Update README configuration, examples, and troubleshooting.
6. Verify tests, build, and coverage.

Rollback is to restore the old separate API key and auth key configuration, but doing so would reintroduce the two-secret startup model.

## Open Questions

- What exact env var name should be preferred: `TAILSCALE_OAUTH_TOKEN`, `TAILSCALE_CREDENTIAL`, or another operator-facing name?
- Which Tailscale read endpoint is the best low-risk validation call across all intended scopes?
- Does tsnet accept the exact OAuth/federated credential form operators will supply, or does it require deriving/using an auth-key-like credential from that identity?
