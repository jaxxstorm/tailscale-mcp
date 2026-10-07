# Aperture Guide

## Endpoints And Identity

Aperture is disabled by default. Enable its independent Streamable HTTP MCP server at `/aperture/mcp` with the boolean `--aperture` / `TS_MCP_APERTURE`. `--aperture=true` enables its HTTP route, five tools, upstream client, and startup endpoint URL logs; `--aperture=false` overrides `TS_MCP_APERTURE=true`. For example, with the existing credentials and tags configured:

```bash
./ts-mcp --aperture=true --aperture-url http://ai/aperture
```

Setting `--aperture-url` or `APERTURE_URL` alone does not enable Aperture. When disabled, the URL is not validated, no upstream Aperture client or tools are initialized, no Aperture endpoint URLs are logged, and `/aperture/mcp` returns 404 on both tailnet and enabled loopback listeners. Grants cannot enable the service.

Tailscale MCP is independently controlled by boolean `--tailscale` / `TS_MCP_TAILSCALE`, default `true`; `--tailscale=false` overrides an environment value of `true`. When enabled, `/tailscale/mcp` is preferred and `/mcp` remains a backward-compatible alias without a redirect. Both Tailscale paths use the same handler, server, catalog, and session state, with identical grants and transport protections on tailnet and enabled loopback listeners; enabled Aperture remains separate. All enabled routes share each listener and port. The default tailnet URLs use port 8080 over HTTP, or port 443 with `--tls`. Separately opt-in loopback exposes enabled routes on `--local-port` (default 8080), with only operator-configured local grants. See [client URLs](usage.md#claude-desktop-integration).

The catalogs and sessions are separate: use the Aperture route for Aperture tools and the Tailscale route for Tailscale tools, resources, and prompts. Aperture adds **no resources or prompts**. Deprecated stdio is Tailscale-only and initializes neither tsnet nor an Aperture client. It ignores Aperture enablement and its URL, even with `--aperture` or `TS_MCP_APERTURE=true`, and never validates that URL or registers Aperture tools.

`--aperture-url` / `APERTURE_URL` sets the upstream API base, defaulting to `http://ai/aperture`. This is not the client-facing MCP URL and cannot be overridden by a tool argument. When Aperture is enabled in HTTP serving mode, supply a complete HTTP(S) URL without userinfo, query, or fragment. A trailing slash is normalized while preserving the base path. Invalid URLs then fail before HTTP serving, but upstream unavailability does not: there is no live Aperture startup probe, and failed Aperture calls do not prevent Tailscale serving.

For Aperture-only HTTP, run:

```bash
./ts-mcp --tailscale=false --aperture
```

Both `/mcp` and `/tailscale/mcp` return 404 on tailnet and enabled loopback listeners. Tailscale tools, resources, prompts, and Admin API clients are not initialized, Admin API validation is skipped, and no Tailscale MCP endpoint URLs are logged. This mode needs neither `TAILSCALE_TAILNET` nor Admin API read scopes. It still uses shared tsnet transport and identity and requires the existing `TAILSCALE_OAUTH_TOKEN` enrollment credential plus advertised tags where applicable. It is not credential-free and adds no new API key. When Tailscale MCP is enabled, its tailnet configuration and startup tailnet-settings read remain required.

Serving with both services disabled fails before network access. Stdio requires Tailscale enabled and rejects `--stdio --tailscale=false` even with Aperture enabled. Informational `--version` and `--list-groups` remain offline and bypass these serving checks.

Aperture requests dial through the deployment's running tsnet node, including on hosts without a system Tailscale daemon. **Upstream sees the MCP node, not the original MCP caller.** Two independent authorization boundaries apply:

| Boundary | Required Authority |
|---|---|
| Caller to MCP | A matching tool grant under `jaxxstorm.com/cap/mcp`, or explicit local grants on enabled loopback |
| MCP node to Aperture config endpoints | Upstream admin role for get, validate, and replace |
| MCP node to Aperture pricing endpoints | Explicit upstream `read_pricing: true`, even for an admin |

The node's roles do not authorize downstream callers, and a caller grant cannot overcome missing upstream roles. Do not confuse these roles with the Tailscale Admin API OAuth scopes. No Admin API authorization, incoming cookies, caller identity headers, or arbitrary caller headers are forwarded. Requests disable redirects and environment proxies, use normal HTTPS certificate verification, propagate cancellation, have a 30-second timeout, and limit upstream responses to 16 MiB.

## Tools And Inputs

These five explicit mappings cover the cached contract. Paths below are relative to the configured API base (normally `/aperture`). Each tool name is also its **exact permission string** in the capability's `tools` array; do not add a `tool:` prefix.

| Tool / Exact Permission | API Operation (Operation ID) | Group | Read-Only | Inputs |
|---|---|---|---|---|
| `aperture_get_config` | `GET /config` (`get-config`) | `aperture-config` | Yes | None |
| `aperture_validate_config` | `POST /config:validate` (`validate-config`) | `aperture-config` | Yes | Required nonblank `config` string |
| `aperture_set_config` | `PUT /config` (`set-config`) | `aperture-config` | No; destructive | Required nonblank `config`, concrete `if_match`, and exact `confirm` strings |
| `aperture_get_pricing` | `GET /pricing` (`get-pricing`) | `aperture-pricing` | Yes | Optional `if_none_match` string |
| `aperture_get_model_pricing` | `GET /pricing/{model}` (`get-model-pricing`) | `aperture-pricing` | Yes | Required nonblank `model` string; optional `if_none_match` string |

The four non-mutating tools have `readOnlyHint=true`. Validation remains read-only despite using POST: it checks a candidate without saving it. Replacement has `readOnlyHint=false` and `destructiveHint=true`. Client annotations are advisory; grants, input checks, confirmation, and concurrency safeguards are enforced server-side before backend access.

Read-only does not mean non-sensitive. Config reads expose upstream-redacted configuration, and validation inputs can contain provider secrets. Review MCP client transcripts, model context, tracing, and retention before submitting secrets, even though server diagnostics are sanitized.

## Grants And Discovery

For example, this value inside a Tailscale grant's `app` object allows only the exact-model pricing tool:

```json
{
  "jaxxstorm.com/cap/mcp": [{
    "tools": ["aperture_get_model_pricing"],
    "resources": []
  }]
}
```

Loopback uses the same selectors in a single local-grant object, without the capability-key wrapper. For a pricing-only local client, start HTTP with existing credentials and tags plus:

```bash
./ts-mcp --aperture --local-http \
  --local-grants '{"tools":["group:aperture-pricing:read"],"resources":[]}'
```

With Tailscale enabled by default, both services open on loopback, but these grants authorize only Aperture pricing. Add `--tailscale=false` to expose only Aperture on both listeners. Every local process able to connect gets those grants; they never authorize tailnet callers.

The following Aperture access applies only when Aperture is enabled in HTTP mode:

| Tool Selector | Aperture Access |
|---|---|
| An exact `aperture_*` tool name | Only that tool |
| `group:aperture-config` | Get, validate, and replace configuration |
| `group:aperture-config:read` | Get and validate configuration, not replacement |
| `group:aperture-pricing` | Both pricing tools |
| `group:aperture-pricing:read` | Both pricing tools |
| `read:*` | Get/validate config and both pricing tools, plus Tailscale readers when enabled |
| `*` | All five Aperture tools, plus every registered Tailscale tool |
| Existing exact Tailscale names or Tailscale groups | No Aperture access |

Selectors have OR semantics, not intersection. For example, combining `read:*` with `group:aperture-config` permits every reader plus config replacement. Unknown groups and unsupported selectors match nothing; arbitrary glob patterns are not supported. Missing grants authorize nothing and malformed grants fail closed. Tool grants confer no resource access.

**Audit broad grants before enabling Aperture.** Existing `*` and `read:*` policies expand to matching Aperture tools only when Aperture is enabled in HTTP mode. Disabled Aperture tools are absent from registration and catalogs; neither wildcard, group, nor exact grants enable them. Prefer exact tools or reviewed service groups when expansion is unwanted. Groups can also expand as new tools are added in future releases. Replacement still requires its ETag and confirmation regardless of the selector used.

Discovery is caller-filtered on each route. Direct invocation of an ungranted tool is denied before backend access, even if the MCP node is an upstream admin. Permissions are evaluated for each request; session IDs never carry or transfer grants. Inspect metadata offline without credentials, tsnet startup, schema downloads, or upstream calls:

```bash
./ts-mcp --list-groups --aperture=false    # Tailscale only, even if env is true
./ts-mcp --list-groups --aperture          # Both HTTP catalogs
./ts-mcp --list-groups --tailscale=false --aperture  # Aperture only
./ts-mcp --list-groups --tailscale=false --aperture=false  # []
./ts-mcp --list-groups --stdio --aperture  # Tailscale only; Aperture ignored
./ts-mcp --list-groups --stdio --tailscale=false --aperture  # []
```

Plain `--list-groups` lists only Tailscale by default; disabled Tailscale is omitted, and Aperture is included only when enabled by flag or environment and `--stdio` is absent. Both disabled is allowed and returns `[]`; stdio listing also returns `[]` when Tailscale is disabled, regardless of Aperture enablement. The output remains deterministic and retains the existing JSON entry shape for tool names, groups, and read-only classification. It describes registered tools, not one caller's effective access. Grants cannot register either disabled service.

## Safe Configuration Replacement

`aperture_get_config` returns a structured result containing a backend-redacted HuJSON `config` string and the exact upstream `etag`. Config validators may be Aperture's unquoted 16-character hexadecimal version or a quoted strong HTTP ETag. Preserve the value exactly: do not add or remove quotes before passing it as `if_match`. Missing validators, weak ETags, wildcards, and ETag lists are rejected. `aperture_validate_config` accepts a HuJSON string and returns `valid` and sanitized `errors` without saving configuration.

**Replacement is destructive, not a merge or patch.** Redacted read-back configuration is not guaranteed to be safe to write back unchanged. Prepare a valid full replacement with appropriate provider-key handling; do not assume redaction placeholders preserve keys or that the MCP server reconstructs them. Confirm any placeholder behavior with the upstream deployment rather than relying on undocumented semantics.

1. Read with `aperture_get_config` and retain its exact ETag.
2. Prepare the full replacement and handle provider secrets securely. Do not use redacted output blindly as a replacement template.
3. Validate the candidate using `aperture_validate_config` with `{"config":"<full HuJSON configuration>"}`. Validation does not reserve the ETag or prevent concurrent edits.
4. Only after explicit operator approval, call `aperture_set_config` with that full `config`, the previously read ETag as `if_match`, and `confirm` exactly equal to `aperture_set_config`.
5. On success, inspect the backend-redacted saved `config` and new `etag`. Retain the new validator for any later deliberate write.

The following illustrates MCP `tools/call` parameters only, **not a runnable replacement or verification step**. Replace both placeholders with reviewed values; never send this literal configuration:

```json
{
  "name": "aperture_set_config",
  "arguments": {
    "config": "<complete reviewed HuJSON replacement>",
    "if_match": "\"<exact-etag-from-get-config>\"",
    "confirm": "aperture_set_config"
  }
}
```

Missing, non-string, or blank required inputs, a wrong confirmation token, malformed ETags, wildcard `*`, and ETag lists are rejected before upstream access. A single concrete ETag is forwarded unchanged as `If-Match`; only `{"config": ...}` is sent in the PUT body. MCP request JSON, including escaped config text, must also fit the shared 4 MiB HTTP request-body limit.

A 412 means the configuration changed concurrently. Read again, review the differences, and decide deliberately whether to validate and submit a new replacement. The server does not silently fetch a fresh ETag, overwrite, merge, or automatically retry writes. A timeout, cancellation, or lost write response has an **uncertain outcome**: the write may have applied. Inspect authoritative state before retrying; an error does not imply rollback. Rolling back the MCP binary also does not undo an upstream write.

## Pricing Results

Use `aperture_get_pricing` for the full catalog or `aperture_get_model_pricing` for one exact identifier. Example MCP `tools/call` parameters:

```json
{
  "name": "aperture_get_model_pricing",
  "arguments": {"model": "provider/model"}
}
```

Slash-separated model identifiers are supported. Reserved characters are safely encoded; empty segments and dot traversal segments are rejected. Model lookup is exact, not fuzzy search or a filter expression. An empty `models` object is a successful result with no useful pricing, not an invented 404.

Both tools optionally accept `if_none_match`, sent as `If-None-Match`. A normal result contains `data`, `etag`, and `not_modified: false`. A bodyless 304 returns `etag` and `not_modified: true` without decoding a body; if the response omits ETag, the submitted validator is returned. Retain prior data in the client when handling not-modified responses.

HuJSON pricing is normalized into structured JSON while preserving decimal price strings, units, cost bases, models, and configured adjustments. No pagination or model-access filtering is invented. If the full catalog exceeds the 16 MiB upstream response limit, use exact-model lookup; the server reports an error rather than returning a truncated catalog as complete.

## Errors And Troubleshooting

A 404 at `/aperture/mcp` on either listener is expected when Aperture is disabled. Enable it with `--aperture` or `TS_MCP_APERTURE=true`, check for a `--aperture=false` override, and use HTTP rather than stdio. Configuring only the upstream URL or MCP grants is insufficient.

Failures are protocol or tool errors, not successful error text. Sanitized HTTP status classification distinguishes upstream 403 (missing node authority), 412 (ETag conflict), 422 (invalid input), and 5xx (upstream failure). Raw upstream Problem Details bodies and untrusted error values/details/messages are not returned because they may echo submitted provider secrets. Validation diagnostics use generic guidance rather than reflecting arbitrary upstream messages or field locations. Submitted config and credentials must not appear in server errors, panic results, or logs.

For pricing 403, check the MCP node's explicit `read_pricing: true` first; admin alone does not suffice. For config 403, check its admin role. Separately verify the caller's exact MCP grants and target route. An unreachable Aperture service or malformed, truncated, or oversized response fails that tool call without turning it into partial success or preventing enabled Tailscale operations. Existing `/mcp` clients continue to use Tailscale only while that service is enabled; Aperture calls require the separate `/aperture/mcp` endpoint. A 404 on either Tailscale alias is expected with `--tailscale=false`.

## Offline Contract And Refresh

The authoritative development contract is the checked-in `tools/aperture/openapi.json`, not a schema fetched at runtime. `tools/aperture/snapshot-metadata.yaml` records source URL, retrieval date, SHA-256, API title/version, OpenAPI version, and operation/path counts. The initial snapshot is from the tailnet-only `http://ai/aperture/openapi.json`, retrieved 2026-10-06, with OpenAPI 3.1.0, API version `0`, five operations, and four paths. Consult the metadata for the current checksum and provenance rather than relying on a copied digest here.

Routine `go build ./...`, `go test ./...`, `go test -race ./...`, and `make coverage` use local contract data and **never fetch the live Aperture schema**. Startup, tool registration, offline `--list-groups`, and tool invocation do not download it either. Mocked upstream tests support development away from the tailnet. This does not remove normal Go dependency requirements or the server's existing startup credential checks.

Only refresh intentionally from an environment connected to the source tailnet:

```bash
make aperture-openapi-refresh
```

This explicit command downloads a temporary candidate and validates JSON, OpenAPI identity, and operation inventory before replacing the snapshot and metadata. Download or validation failure leaves the previous cache intact. It is not a routine build, test, coverage, or deployment step, and should not run as a live verification shortcut. `make openapi-refresh` remains the separate, unchanged Tailscale refresh workflow.

After an intentional refresh:

1. Review the schema diff and metadata together, including source, retrieval date, versions, counts, and SHA-256. Locally check the digest with `shasum -a 256 tools/aperture/openapi.json` and compare it with the metadata.
2. Review operation coverage against the five-tool table above and production registrations: method, path, operation ID, exact tool name, group, and mutation classification must each match exactly once. Offline contract tests detect missing, duplicate, or stale mappings and metadata drift.
3. Treat any new upstream operation as a reviewed implementation and permission change, not automatic exposure. Update mappings, tests, grants guidance, and this table together; review wildcard/group expansion before release.
4. Run offline tests and coverage checks. Keep Aperture contract review separate from the generated Tailscale coverage reports; do not regenerate or edit those reports merely to document Aperture.

Live smoke tests are optional and require both upstream node roles and MCP caller grants. Prefer non-mutating tools; never perform a live configuration replacement without explicit operator approval and a prepared full replacement.
