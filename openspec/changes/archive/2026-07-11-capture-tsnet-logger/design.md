## Context

The server initializes a Zap logger early and uses it for MCP startup, HTTP request, authorization, and error logs. tsnet still emits startup and lifecycle messages through its own logging hooks, which currently fall back to standard-library log output and produce mixed log formats alongside application logs.

This change only affects local runtime logging for the tsnet-backed Streamable HTTP transport. It does not add Tailscale OpenAPI coverage, change MCP tool/resource registrations, or alter grant enforcement.

## Goals / Non-Goals

**Goals:**

- Route tsnet user-visible logs through the existing application logger.
- Keep verbose tsnet/backend logs quiet by default and enable them when debug logging is requested.
- Preserve current tsnet startup behavior, state directory behavior, build metadata registration, credential handling, Streamable HTTP serving, and stdio compatibility.
- Keep tests focused on logger adapter behavior and tsnet server configuration.

**Non-Goals:**

- Changing the global logger format or log level policy.
- Parsing every tsnet message into structured fields.
- Adding a new CLI flag or environment variable for tsnet logging.
- Changing MCP authorization, grant names, OpenAPI mappings, tools, resources, or prompts.

## Decisions

1. Adapt tsnet's `logger.Logf` shape to Zap.

Create a small helper that accepts a Zap logger and level, then returns a printf-style function suitable for tsnet's `UserLogf` and `Logf` fields. The helper should format the message once and attach it as a `message` field or emit it as the log message with a stable `component` field such as `tsnet`.

Alternative considered: redirect the standard library logger globally. This is broader than needed and risks changing logs from unrelated dependencies.

2. Use `UserLogf` for normal tsnet lifecycle messages.

Set `tsnet.Server.UserLogf` so startup messages like state path, hostname, login state, and auth loop messages go through the same Zap output as the MCP server.

Alternative considered: only set `Logf`. tsnet separates user-visible and backend logs; user-visible messages are the ones operators see during startup.

3. Gate verbose backend logs on debug mode.

Set `tsnet.Server.Logf` only when debug logging is enabled. This preserves the current non-debug behavior while giving operators a single logging surface for deeper tsnet diagnostics when requested.

Alternative considered: always route backend logs at debug level. Even if debug entries are filtered, constructing and passing every backend message may add noise and overhead with no operator benefit.

4. Keep stdio mode unaffected.

Stdio exits before tsnet starts, so tsnet logger wiring belongs in the tsnet server construction path and should not change stdio logging behavior.

## Risks / Trade-offs

- tsnet messages may still be unstructured text inside a structured Zap record. Mitigation: keep a stable `component=tsnet` field so they are easy to filter.
- Debug mode may produce substantial backend tsnet logs. Mitigation: only enable backend `Logf` when the existing debug flag is set.
- Tests should avoid starting a real tsnet server. Mitigation: test the adapter function and constructed `tsnet.Server` fields directly.
