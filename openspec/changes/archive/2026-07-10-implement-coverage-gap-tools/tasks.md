## 1. Shared API Infrastructure

- [x] 1.1 Add a generic Tailscale Admin API helper for authenticated JSON requests using configured API key and tailnet.
- [x] 1.2 Add endpoint definition types for read tools/resources, including operation ID, method, path template, input schema, grant names, and coverage metadata.
- [x] 1.3 Add shared handler logic that expands path/query parameters, calls the API helper, and returns structured JSON or sanitized API errors.
- [x] 1.4 Refactor existing tool/resource registration into grouped helper functions without changing current behavior.

## 2. Read Tool Registration

- [x] 2.1 Register read tools for Contacts and DNS operations.
- [x] 2.2 Register read tools for DeviceInvites, UserInvites, Users, and OAuthApps operations.
- [x] 2.3 Register read tools for DevicePosture and additional Devices read operations.
- [x] 2.4 Register read tools for Keys, Webhooks, and Services operations.
- [x] 2.5 Register read tools for Logging operations, including read-like AWS external ID validation exceptions.
- [x] 2.6 Register read tools for PolicyFile preview/validation only if they are treated as explicit read-like validation operations; otherwise keep them as gaps.

## 3. Resource Registration

- [x] 3.1 Add resources for stable DNS configuration, nameservers, preferences, search paths, and split DNS state.
- [x] 3.2 Add resources for users, invites, keys, webhooks, services, and posture integration collections/entities where URI templates are natural.
- [x] 3.3 Add resources for device routes and posture attributes where parameterized entity access is useful.
- [x] 3.4 Ensure every resource checks resource grants before calling the Tailscale API.

## 4. Coverage Metadata

- [x] 4.1 Update `tools/coverage/mappings.go` for every newly implemented read tool/resource.
- [x] 4.2 Implement mutating operations as guarded tools with explicit confirmation tokens rather than leaving them as gaps.
- [x] 4.3 Run `make coverage` and verify read operations move from gap to implemented with grant names and rationale.
- [x] 4.4 Update `coverage/parity-backlog.md` and `coverage/mcp-coverage.md` from generated output.

## 5. Verification

- [x] 5.1 Add unit tests for path/query expansion and sanitized API error formatting.
- [x] 5.2 Add tests that read endpoint definitions have unique operation IDs, tool names, and grant permissions.
- [x] 5.3 Add tests that implemented coverage mappings correspond to registered read definitions.
- [x] 5.4 Add tests that unauthorized tool/resource calls do not invoke the API helper.
- [x] 5.5 Run `go test ./...`, `go build ./...`, and `make coverage`.

## 6. Documentation

- [x] 6.1 Update README tool/resource tables or generated documentation for newly implemented read endpoints.
- [x] 6.2 Document full coverage and confirm-token requirements for mutating operations.
- [x] 6.3 Document grant naming for new tools and resources.
