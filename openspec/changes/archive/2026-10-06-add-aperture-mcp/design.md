## Context

The application currently constructs one Tailscale MCP server and one Streamable HTTP handler at `/mcp`. Tailnet and opt-in loopback listeners share that surface, with different trusted grant sources. Tool catalogs are server-local; grants use `jaxxstorm.com/cap/mcp`. Deprecated stdio uses the same Tailscale surface without starting tsnet.

The downloaded Aperture OpenAPI 3.1 snapshot defines five operations on four paths under `/aperture`. It authenticates through Tailscale identity, not an API token. Configuration operations require upstream admin; pricing requires explicit `read_pricing: true`, even for admins. The API documents HuJSON configuration and pricing, ETags, conditional requests, and RFC 9457 errors. It has no pagination parameters.

## Goals / Non-Goals

**Goals:**
- Expose independent Tailscale and Aperture MCP surfaces on the same HTTP listeners.
- Cover all five cached Aperture operations with typed, grant-controlled tools and safe configuration replacement.
- Preserve Tailscale semantics, transport protections, lifecycle handling, and offline development.

**Non-Goals:**
- LLM inference/proxy APIs, extra Aperture endpoints absent from the snapshot, or dynamically generated runtime tools.
- New Tailscale Admin operations, changes to upstream credentials, or end-user identity delegation.
- Aperture resources, prompts, stdio selection, multiple Aperture instances, or a generic plugin/profile framework.
- An Aperture-only deployment mode that removes current Tailscale startup requirements.

## Decisions

### Separate servers behind a shared router

Construct two `MCPServer` instances with separate catalogs and separate Streamable HTTP handlers. Mount the same Tailscale handler instance at both `/tailscale/mcp` (preferred explicit route) and `/mcp` (backward-compatible alias), without a redirect or a second Tailscale server or handler. Both paths dispatch directly to the same Tailscale server, catalog, and SDK/session state; SDK endpoint configuration must support requests on either path. Mount the independent Aperture handler at `/aperture/mcp`. Each service's handler is shared between tailnet and loopback just as today, but no SDK/session state is shared between services. Session identifiers never convey identity or permission; every request is authorized afresh. Tailscale sessions work across its two aliases, but cannot attach to Aperture state or vice versa.

Retain the common Host, Origin, logging, bounded body ingestion, and listener shutdown stack. Apply the existing trusted grant middleware to all paths, with identical grants and transport protections for both Tailscale aliases on tailnet and enabled loopback listeners. Tailnet requests use identity-derived grants; loopback requests use only explicit local grants. Log each full endpoint URL. Preserve Tailscale names, resources, prompts, mutation checks, and stdio behavior. Prefer small edits to existing construction/routing helpers over moving all existing Tailscale source files or inventing a backend registry.

Alternative: one merged MCP server would leak service discovery across services. A second listener would contradict the shared-port requirement. Redirecting `/mcp` or constructing a second Tailscale handler would not satisfy direct backward compatibility with shared session state.

### Cache the API contract, not a live runtime dependency

Use `tools/aperture/openapi.json` as the checked-in contract, with `snapshot-metadata.yaml` recording source URL, retrieval date, version, SHA-256, and operation/path counts. Add an explicit refresh command that downloads to a temporary file, validates JSON, OpenAPI identity, and operation inventory before replacing the snapshot and metadata; failures leave the previous snapshot intact. The download must run only on operator request while connected to the tailnet, never at build, startup, test, or tool invocation time.

Use a small explicit five-operation mapping rather than adding a generic OpenAPI generator. Test that its operation IDs, paths, methods, tool names, groups, and mutation classifications cover the cached contract exactly, and document that mapping. Any new upstream operation requires reviewed mappings and grants, not automatic exposure.

### Dedicated upstream client using the deployment's tsnet identity

Add `--aperture-url` / `APERTURE_URL`, default `http://ai/aperture`. Validate a complete HTTP(S) URL before serving; reject userinfo, query, and fragment. Normalize a trailing slash without losing the `/aperture` prefix. The URL is operator configuration, never a tool argument. Always expose the Aperture HTTP route; no live availability check is required for startup. Stdio remains Tailscale-only and does not initialize an Aperture client or tsnet.

In HTTP mode, use an injected `http.Client` whose transport dials through the already-running tsnet server (`Dial`), allowing the same node identity on hosts without a system Tailscale daemon. Extend the existing tailnet interface and its test fakes minimally. Disable proxy-from-environment and redirects, retain normal HTTPS certificate verification, bound requests to 30 seconds and responses to 16 MiB, and propagate request cancellation. Tests inject a fake transport/client and never require a tailnet.

Do not attach Admin API authorization, incoming cookies, caller identity headers, or arbitrary caller headers. Document that the upstream sees the MCP node: that node needs admin and/or `read_pricing`, while MCP grants decide which downstream callers may use that authority. Unreachable upstreams fail individual tool calls; they do not stop the shared server.

Alternative: using the host network client could silently use a different node identity and fail on tsnet-only deployments. Forwarding caller headers would not provide authentic Tailscale delegation. Reusing the Admin API client would send unrelated credentials.

### Explicit operation and permission mapping

Each exact tool name is also its exact grant permission. Existing selector evaluation remains unchanged and is applied against the route's own catalog.

| Operation | Tool / exact permission | Group | Read-only | Inputs |
| --- | --- | --- | --- | --- |
| `GET /config` (`get-config`) | `aperture_get_config` | `aperture-config` | yes | none |
| `POST /config:validate` (`validate-config`) | `aperture_validate_config` | `aperture-config` | yes | required `config` string |
| `PUT /config` (`set-config`) | `aperture_set_config` | `aperture-config` | no | required `config`, `if_match`, `confirm` strings |
| `GET /pricing` (`get-pricing`) | `aperture_get_pricing` | `aperture-pricing` | yes | optional `if_none_match` string |
| `GET /pricing/{model}` (`get-model-pricing`) | `aperture_get_model_pricing` | `aperture-pricing` | yes | required `model`, optional `if_none_match` strings |

Config validation is non-mutating and therefore included in read selectors; tool descriptions explicitly warn that config inputs may contain provider secrets. Broad `*` and `read:*` retain their existing meaning across registered tools, including Aperture. Existing Tailscale exact names/groups cannot match Aperture names/groups. This is documented as a permission expansion to audit before rollout. Use the existing strict grant schema without adding service fields. No resources or prompts are registered on the Aperture server.

`--list-groups` in HTTP configuration combines metadata from both independently validated catalogs in deterministic order while preserving its current JSON entry shape. With `--stdio`, it lists only Tailscale. It must remain usable without credentials, tsnet initialization, schema fetches, or upstream calls.

### Configuration mutation is explicit and concurrency protected

Return structured objects containing the redacted `config` string and exact upstream `etag` from get/set. Validation submits `{config: ...}` without saving and returns `valid` and `errors`. Reject missing, non-string, or blank required inputs before upstream access. Require `confirm` to equal `aperture_set_config` and a concrete `if_match` ETag from a previous get; reject `*` and ETag lists so callers cannot bypass stale-write protection. Forward that ETag exactly as `If-Match` and send only `{config: ...}` as the upstream body.

Treat replacement as destructive, not an automatic merge. Describe that read-back configuration contains redacted provider keys and is not guaranteed to be safe to write back unchanged; callers must supply a valid full replacement with appropriate key handling. Do not infer how upstream redaction placeholders are interpreted. Do not auto-fetch a newer ETag, retry writes, or overwrite on 412. A timeout after a write is an uncertain outcome: instruct the caller to inspect state before retrying. No success claim or rollback is fabricated.

### Bounded structured results and errors

Preserve config strings as HuJSON. Parse pricing using HuJSON normalization before JSON decoding if needed, retaining decimal price strings and the catalog's units, cost bases, models, and configured adjustments. Return `{data, etag, not_modified: false}` for pricing success; 304 yields `{etag, not_modified: true}` without decoding an absent body. If a 304 omits ETag, use the submitted validator. Per-model lookup forwards one exact model, preserving slash-separated model identifiers with safe path construction; reject empty/dot traversal segments and encode reserved characters rather than allowing query/path injection. An empty `models` object is a successful lookup with no useful pricing, not a 404 invented by the MCP layer.

No pagination or filtering is invented: full pricing uses its bounded response, and exact-model pricing provides the narrower alternative. An oversized, truncated, malformed, or unexpected response is a tool error, not partial success. Preserve HTTP status and safe Problem Details classification for 403, 412, 422, and 5xx responses. Do not forward raw backend bodies or untrusted error `value`/`detail`/`message` fields that may echo provider secrets. Return sanitized status-specific guidance and safe validation field locations, with no submitted configuration or credentials in logs, panic results, or errors. Validation success payloads include upstream validation messages only after secret-aware sanitization against submitted config; if safety cannot be established, return generic validation guidance instead. This trades some diagnostic fidelity for preventing credential leakage.

## Risks / Trade-offs

- [Existing wildcard grants acquire Aperture access] -> Document explicitly, recommend exact tools or service groups, and test both broad and narrow grants. Require operators to audit grants before rollout.
- [MCP node admin authority exceeds caller authority] -> Enforce request-specific discovery and direct-call checks before all backend calls; upstream role checks remain an independent second boundary.
- [Schema is tailnet-local and may drift] -> Retain source/checksum metadata, explicit refresh, and coverage tests; never depend on the live endpoint for builds.
- [Redacted config is not a safe replacement template] -> Warn in tool descriptions, preserve ETags, require explicit confirmation, and never silently merge or reuse redaction placeholders.
- [Large pricing catalog exceeds bounds] -> Fail explicitly and recommend exact-model lookup; do not truncate or present incomplete data as complete.
- [Two SDK handlers complicate sessions and shutdown] -> Test cross-service isolation, Tailscale session reuse across aliases, per-request grant changes, both listener types, and simultaneous open streams.
- [Alias routing could diverge in state or protections] -> Mount the same Tailscale handler and apply identical middleware on both paths; test direct handling without redirects and shared sessions on both listener types.

## Migration Plan

1. Keep the reviewed schema snapshot in the repository and implement against offline fixtures.
2. Audit existing broad MCP grants and grant the tsnet node the intended Aperture upstream roles. Configure `APERTURE_URL` if the node is not `ai`.
3. Deploy without changing existing `/mcp` clients; prefer `/tailscale/mcp` for new configurations. Add a separate client entry for `/aperture/mcp` on the same host/port. Local clients use the corresponding paths on the existing opt-in loopback port.
4. Verify Tailscale alias equivalence, cross-service isolation, and authorization offline, then optionally smoke-test non-mutating calls on the tailnet. Do not run a live configuration replacement without explicit operator approval and a prepared replacement.
5. Roll back by deploying the previous binary. If it supports only `/mcp`, change clients using `/tailscale/mcp` to `/mcp`; existing `/mcp` clients need no URL change. Remove unsupported Aperture entries/options. Rolling back the MCP server does not revert any upstream configuration writes.

## Open Questions

No blocking API-contract questions remain for these five operations. Live deployment must confirm the chosen MCP node's Aperture roles and any upstream redacted-key replacement behavior; the implementation must not depend on undocumented placeholder semantics.
