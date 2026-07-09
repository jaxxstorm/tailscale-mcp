# MCP Coverage

Source: `tools/coverage/tailscale-v2-openapi.yaml`

| Total | Implemented | Gaps | Excluded | Planned |
|---:|---:|---:|---:|---:|
| 90 | 4 | 86 | 0 | 0 |

## Contacts

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| gap | GET | `/tailnet/{tailnet}/contacts` | `getContacts` | tool | `` | No MCP mapping implemented yet. |
| gap | PATCH | `/tailnet/{tailnet}/contacts/{contactType}` | `updateContact` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/contacts/{contactType}/resend-verification-email` | `resendContactVerificationEmail` | tool | `` | No MCP mapping implemented yet. |

## DNS

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| gap | GET | `/tailnet/{tailnet}/dns/configuration` | `getDnsConfiguration` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/dns/configuration` | `setDnsConfiguration` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/dns/nameservers` | `listDnsNameservers` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/dns/nameservers` | `setDnsNameservers` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/dns/preferences` | `getDnsPreferences` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/dns/preferences` | `setDnsPreferences` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/dns/searchpaths` | `listDnsSearchPaths` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/dns/searchpaths` | `setDnsSearchPaths` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/dns/split-dns` | `getSplitDns` | tool | `` | No MCP mapping implemented yet. |
| gap | PATCH | `/tailnet/{tailnet}/dns/split-dns` | `updateSplitDns` | tool | `` | No MCP mapping implemented yet. |
| gap | PUT | `/tailnet/{tailnet}/dns/split-dns` | `setSplitDns` | tool | `` | No MCP mapping implemented yet. |

## DeviceInvites

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| gap | POST | `/device-invites/-/accept` | `acceptDeviceInvite` | tool | `` | No MCP mapping implemented yet. |
| gap | DELETE | `/device-invites/{deviceInviteId}` | `deleteDeviceInvite` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/device-invites/{deviceInviteId}` | `getDeviceInvite` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/device-invites/{deviceInviteId}/resend` | `resendDeviceInvite` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/device/{deviceId}/device-invites` | `listDeviceInvites` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/device/{deviceId}/device-invites` | `createDeviceInvites` | tool | `` | No MCP mapping implemented yet. |

## DevicePosture

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| gap | DELETE | `/posture/integrations/{id}` | `deletePostureIntegration` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/posture/integrations/{id}` | `getPostureIntegration` | tool | `` | No MCP mapping implemented yet. |
| gap | PATCH | `/posture/integrations/{id}` | `updatePostureIntegration` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/posture/integrations` | `getPostureIntegrations` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/posture/integrations` | `createPostureIntegration` | tool | `` | No MCP mapping implemented yet. |

## Devices

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| gap | DELETE | `/device/{deviceId}` | `deleteDevice` | tool | `` | No MCP mapping implemented yet. |
| implemented | GET | `/device/{deviceId}` | `getDevice` | tool: `get_device_info`: `tailscale://device/{device}` | `tool:get_device_info` | Parameterized device lookup by ID, hostname, or IP is exposed as a typed tool with a matching resource shape. |
| gap | GET | `/device/{deviceId}/attributes` | `getDevicePostureAttributes` | tool | `` | No MCP mapping implemented yet. |
| gap | DELETE | `/device/{deviceId}/attributes/{attributeKey}` | `deleteCustomDevicePostureAttributes` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/device/{deviceId}/attributes/{attributeKey}` | `setCustomDevicePostureAttributes` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/device/{deviceId}/authorized` | `authorizeDevice` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/device/{deviceId}/expire` | `expireDeviceKey` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/device/{deviceId}/ip` | `setDeviceIp` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/device/{deviceId}/key` | `updateDeviceKey` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/device/{deviceId}/name` | `setDeviceName` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/device/{deviceId}/routes` | `listDeviceRoutes` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/device/{deviceId}/routes` | `setDeviceRoutes` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/device/{deviceId}/tags` | `setDeviceTags` | tool | `` | No MCP mapping implemented yet. |
| gap | PATCH | `/tailnet/{tailnet}/device-attributes` | `batchUpdateCustomDevicePostureAttributes` | tool | `` | No MCP mapping implemented yet. |
| implemented | GET | `/tailnet/{tailnet}/devices` | `listTailnetDevices` | tool: `list_all_devices`: `tailscale://devices` | `tool:list_all_devices` | Device collection is exposed as both a Claude-compatible tool and a stable resource. |

## Keys

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| gap | GET | `/tailnet/{tailnet}/keys` | `listTailnetKeys` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/keys` | `createKey` | tool | `` | No MCP mapping implemented yet. |
| gap | DELETE | `/tailnet/{tailnet}/keys/{keyId}` | `deleteKey` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/keys/{keyId}` | `getKey` | tool | `` | No MCP mapping implemented yet. |
| gap | PUT | `/tailnet/{tailnet}/keys/{keyId}` | `setKey` | tool | `` | No MCP mapping implemented yet. |

## Logging

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| gap | POST | `/tailnet/{tailnet}/aws-external-id` | `getAwsExternalId` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/aws-external-id/{id}/validate-aws-trust-policy` | `validateAwsExternalId` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/logging/configuration` | `listConfigurationAuditLogs` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/logging/network` | `listNetworkFlowLogs` | tool | `` | No MCP mapping implemented yet. |
| gap | DELETE | `/tailnet/{tailnet}/logging/{logType}/stream` | `disableLogStreaming` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/logging/{logType}/stream` | `getLogStreamingConfiguration` | tool | `` | No MCP mapping implemented yet. |
| gap | PUT | `/tailnet/{tailnet}/logging/{logType}/stream` | `setLogStreamingConfiguration` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/logging/{logType}/stream/status` | `getLogStreamingStatus` | tool | `` | No MCP mapping implemented yet. |

## OAuthApps

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| gap | GET | `/tailnet/{tailnet}/oauth-apps` | `listOAuthApps` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/oauth-apps` | `createOAuthApp` | tool | `` | No MCP mapping implemented yet. |
| gap | DELETE | `/tailnet/{tailnet}/oauth-apps/{appId}` | `deleteOAuthApp` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/oauth-apps/{appId}` | `getOAuthApp` | tool | `` | No MCP mapping implemented yet. |
| gap | PUT | `/tailnet/{tailnet}/oauth-apps/{appId}` | `updateOAuthApp` | tool | `` | No MCP mapping implemented yet. |

## PolicyFile

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | GET | `/tailnet/{tailnet}/acl` | `getPolicyFile` | resource: `tailscale://policy` | `resource:tailscale://policy` | Policy file is stable tailnet state exposed as JSON. |
| gap | POST | `/tailnet/{tailnet}/acl` | `setPolicyFile` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/acl/preview` | `previewRuleMatches` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/acl/validate` | `validateAndTestPolicyFile` | tool | `` | No MCP mapping implemented yet. |

## Services

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| gap | GET | `/tailnet/{tailnet}/services` | `listServices` | tool | `` | No MCP mapping implemented yet. |
| gap | DELETE | `/tailnet/{tailnet}/services/{serviceName}` | `deleteService` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/services/{serviceName}` | `getService` | tool | `` | No MCP mapping implemented yet. |
| gap | PUT | `/tailnet/{tailnet}/services/{serviceName}` | `updateService` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved` | `getServiceDeviceApproval` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved` | `updateServiceDeviceApproval` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/tailnet/{tailnet}/services/{serviceName}/devices` | `listServiceHosts` | tool | `` | No MCP mapping implemented yet. |

## TailnetSettings

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | GET | `/tailnet/{tailnet}/settings` | `getTailnetSettings` | resource: `tailscale://tailnet-settings` | `resource:tailscale://tailnet-settings` | Tailnet settings are stable tailnet state exposed as JSON. |
| gap | PATCH | `/tailnet/{tailnet}/settings` | `updateTailnetSettings` | tool | `` | No MCP mapping implemented yet. |

## UserInvites

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| gap | GET | `/tailnet/{tailnet}/user-invites` | `listUserInvites` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/user-invites` | `createUserInvites` | tool | `` | No MCP mapping implemented yet. |
| gap | DELETE | `/user-invites/{userInviteId}` | `deleteUserInvite` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/user-invites/{userInviteId}` | `getUserInvite` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/user-invites/{userInviteId}/resend` | `resendUserInvite` | tool | `` | No MCP mapping implemented yet. |

## Users

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| gap | GET | `/tailnet/{tailnet}/users` | `listUsers` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/users/{userId}` | `getUser` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/users/{userId}/approve` | `approveUser` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/users/{userId}/delete` | `deleteUser` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/users/{userId}/restore` | `restoreUser` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/users/{userId}/role` | `updateUserRole` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/users/{userId}/suspend` | `suspendUser` | tool | `` | No MCP mapping implemented yet. |

## Webhooks

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| gap | GET | `/tailnet/{tailnet}/webhooks` | `listWebhooks` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/tailnet/{tailnet}/webhooks` | `createWebhook` | tool | `` | No MCP mapping implemented yet. |
| gap | DELETE | `/webhooks/{endpointId}` | `deleteWebhook` | tool | `` | No MCP mapping implemented yet. |
| gap | GET | `/webhooks/{endpointId}` | `getWebhook` | tool | `` | No MCP mapping implemented yet. |
| gap | PATCH | `/webhooks/{endpointId}` | `updateWebhook` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/webhooks/{endpointId}/rotate` | `rotateWebhookSecret` | tool | `` | No MCP mapping implemented yet. |
| gap | POST | `/webhooks/{endpointId}/test` | `testWebhook` | tool | `` | No MCP mapping implemented yet. |

