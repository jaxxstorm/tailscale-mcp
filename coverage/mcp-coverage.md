# MCP Coverage

Source: `tools/coverage/tailscale-v2-openapi.yaml`

| Total | Implemented | Gaps | Excluded | Planned |
|---:|---:|---:|---:|---:|
| 90 | 90 | 0 | 0 | 0 |

## Contacts

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | GET | `/tailnet/{tailnet}/contacts` | `getContacts` | tool: `tailscale_get_contacts` | `tool:tailscale_get_contacts` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | PATCH | `/tailnet/{tailnet}/contacts/{contactType}` | `updateContact` | tool: `tailscale_update_contact` | `tool:tailscale_update_contact` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/tailnet/{tailnet}/contacts/{contactType}/resend-verification-email` | `resendContactVerificationEmail` | tool: `tailscale_resend_contact_verification_email` | `tool:tailscale_resend_contact_verification_email` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |

## DNS

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | GET | `/tailnet/{tailnet}/dns/configuration` | `getDnsConfiguration` | resource: `tailscale://dns/configuration` | `resource:tailscale://dns/configuration` | Stable tailnet state is exposed as an MCP JSON resource through the generic read API resource registrar. |
| implemented | POST | `/tailnet/{tailnet}/dns/configuration` | `setDnsConfiguration` | tool: `tailscale_set_dns_configuration` | `tool:tailscale_set_dns_configuration` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/tailnet/{tailnet}/dns/nameservers` | `listDnsNameservers` | resource: `tailscale://dns/nameservers` | `resource:tailscale://dns/nameservers` | Stable tailnet state is exposed as an MCP JSON resource through the generic read API resource registrar. |
| implemented | POST | `/tailnet/{tailnet}/dns/nameservers` | `setDnsNameservers` | tool: `tailscale_set_dns_nameservers` | `tool:tailscale_set_dns_nameservers` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/tailnet/{tailnet}/dns/preferences` | `getDnsPreferences` | resource: `tailscale://dns/preferences` | `resource:tailscale://dns/preferences` | Stable tailnet state is exposed as an MCP JSON resource through the generic read API resource registrar. |
| implemented | POST | `/tailnet/{tailnet}/dns/preferences` | `setDnsPreferences` | tool: `tailscale_set_dns_preferences` | `tool:tailscale_set_dns_preferences` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/tailnet/{tailnet}/dns/searchpaths` | `listDnsSearchPaths` | resource: `tailscale://dns/searchpaths` | `resource:tailscale://dns/searchpaths` | Stable tailnet state is exposed as an MCP JSON resource through the generic read API resource registrar. |
| implemented | POST | `/tailnet/{tailnet}/dns/searchpaths` | `setDnsSearchPaths` | tool: `tailscale_set_dns_search_paths` | `tool:tailscale_set_dns_search_paths` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/tailnet/{tailnet}/dns/split-dns` | `getSplitDns` | resource: `tailscale://dns/split-dns` | `resource:tailscale://dns/split-dns` | Stable tailnet state is exposed as an MCP JSON resource through the generic read API resource registrar. |
| implemented | PATCH | `/tailnet/{tailnet}/dns/split-dns` | `updateSplitDns` | tool: `tailscale_update_split_dns` | `tool:tailscale_update_split_dns` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | PUT | `/tailnet/{tailnet}/dns/split-dns` | `setSplitDns` | tool: `tailscale_set_split_dns` | `tool:tailscale_set_split_dns` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |

## DeviceInvites

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | POST | `/device-invites/-/accept` | `acceptDeviceInvite` | tool: `tailscale_accept_device_invite` | `tool:tailscale_accept_device_invite` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | DELETE | `/device-invites/{deviceInviteId}` | `deleteDeviceInvite` | tool: `tailscale_delete_device_invite` | `tool:tailscale_delete_device_invite` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/device-invites/{deviceInviteId}` | `getDeviceInvite` | tool: `tailscale_get_device_invite` | `tool:tailscale_get_device_invite` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | POST | `/device-invites/{deviceInviteId}/resend` | `resendDeviceInvite` | tool: `tailscale_resend_device_invite` | `tool:tailscale_resend_device_invite` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/device/{deviceId}/device-invites` | `listDeviceInvites` | tool: `tailscale_list_device_invites` | `tool:tailscale_list_device_invites` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | POST | `/device/{deviceId}/device-invites` | `createDeviceInvites` | tool: `tailscale_create_device_invites` | `tool:tailscale_create_device_invites` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |

## DevicePosture

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | DELETE | `/posture/integrations/{id}` | `deletePostureIntegration` | tool: `tailscale_delete_posture_integration` | `tool:tailscale_delete_posture_integration` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/posture/integrations/{id}` | `getPostureIntegration` | tool: `tailscale_get_posture_integration` | `tool:tailscale_get_posture_integration` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | PATCH | `/posture/integrations/{id}` | `updatePostureIntegration` | tool: `tailscale_update_posture_integration` | `tool:tailscale_update_posture_integration` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/tailnet/{tailnet}/posture/integrations` | `getPostureIntegrations` | resource: `tailscale://posture/integrations` | `resource:tailscale://posture/integrations` | Stable tailnet state is exposed as an MCP JSON resource through the generic read API resource registrar. |
| implemented | POST | `/tailnet/{tailnet}/posture/integrations` | `createPostureIntegration` | tool: `tailscale_create_posture_integration` | `tool:tailscale_create_posture_integration` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |

## Devices

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | DELETE | `/device/{deviceId}` | `deleteDevice` | tool: `tailscale_delete_device` | `tool:tailscale_delete_device` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/device/{deviceId}` | `getDevice` | tool: `get_device_info`: `tailscale://device/{device}` | `tool:get_device_info` | Parameterized device lookup by ID, hostname, or IP is exposed as a typed tool with a matching resource shape. |
| implemented | GET | `/device/{deviceId}/attributes` | `getDevicePostureAttributes` | resource: `tailscale://device/{deviceId}/attributes` | `resource:tailscale://device/{deviceId}/attributes` | Parameterized device state is exposed as an MCP JSON resource template through the generic read API resource registrar. |
| implemented | DELETE | `/device/{deviceId}/attributes/{attributeKey}` | `deleteCustomDevicePostureAttributes` | tool: `tailscale_delete_custom_device_posture_attributes` | `tool:tailscale_delete_custom_device_posture_attributes` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/device/{deviceId}/attributes/{attributeKey}` | `setCustomDevicePostureAttributes` | tool: `tailscale_set_custom_device_posture_attributes` | `tool:tailscale_set_custom_device_posture_attributes` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/device/{deviceId}/authorized` | `authorizeDevice` | tool: `tailscale_authorize_device` | `tool:tailscale_authorize_device` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/device/{deviceId}/expire` | `expireDeviceKey` | tool: `tailscale_expire_device_key` | `tool:tailscale_expire_device_key` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/device/{deviceId}/ip` | `setDeviceIp` | tool: `tailscale_set_device_ip` | `tool:tailscale_set_device_ip` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/device/{deviceId}/key` | `updateDeviceKey` | tool: `tailscale_update_device_key` | `tool:tailscale_update_device_key` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/device/{deviceId}/name` | `setDeviceName` | tool: `tailscale_set_device_name` | `tool:tailscale_set_device_name` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/device/{deviceId}/routes` | `listDeviceRoutes` | resource: `tailscale://device/{deviceId}/routes` | `resource:tailscale://device/{deviceId}/routes` | Parameterized device state is exposed as an MCP JSON resource template through the generic read API resource registrar. |
| implemented | POST | `/device/{deviceId}/routes` | `setDeviceRoutes` | tool: `tailscale_set_device_routes` | `tool:tailscale_set_device_routes` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/device/{deviceId}/tags` | `setDeviceTags` | tool: `tailscale_set_device_tags` | `tool:tailscale_set_device_tags` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | PATCH | `/tailnet/{tailnet}/device-attributes` | `batchUpdateCustomDevicePostureAttributes` | tool: `tailscale_batch_update_custom_device_posture_attributes` | `tool:tailscale_batch_update_custom_device_posture_attributes` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/tailnet/{tailnet}/devices` | `listTailnetDevices` | tool: `list_all_devices`: `tailscale://devices` | `tool:list_all_devices` | Device collection is exposed as both a Claude-compatible tool and a stable resource. |

## Keys

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | GET | `/tailnet/{tailnet}/keys` | `listTailnetKeys` | resource: `tailscale://keys` | `resource:tailscale://keys` | Stable tailnet state is exposed as an MCP JSON resource through the generic read API resource registrar. |
| implemented | POST | `/tailnet/{tailnet}/keys` | `createKey` | tool: `tailscale_create_key` | `tool:tailscale_create_key` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | DELETE | `/tailnet/{tailnet}/keys/{keyId}` | `deleteKey` | tool: `tailscale_delete_key` | `tool:tailscale_delete_key` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/tailnet/{tailnet}/keys/{keyId}` | `getKey` | tool: `tailscale_get_key` | `tool:tailscale_get_key` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | PUT | `/tailnet/{tailnet}/keys/{keyId}` | `setKey` | tool: `tailscale_set_key` | `tool:tailscale_set_key` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |

## Logging

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | POST | `/tailnet/{tailnet}/aws-external-id` | `getAwsExternalId` | tool: `tailscale_get_aws_external_id` | `tool:tailscale_get_aws_external_id` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/tailnet/{tailnet}/aws-external-id/{id}/validate-aws-trust-policy` | `validateAwsExternalId` | tool: `tailscale_validate_aws_external_id` | `tool:tailscale_validate_aws_external_id` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | GET | `/tailnet/{tailnet}/logging/configuration` | `listConfigurationAuditLogs` | tool: `tailscale_list_configuration_audit_logs` | `tool:tailscale_list_configuration_audit_logs` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | GET | `/tailnet/{tailnet}/logging/network` | `listNetworkFlowLogs` | tool: `tailscale_list_network_flow_logs` | `tool:tailscale_list_network_flow_logs` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | DELETE | `/tailnet/{tailnet}/logging/{logType}/stream` | `disableLogStreaming` | tool: `tailscale_disable_log_streaming` | `tool:tailscale_disable_log_streaming` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/tailnet/{tailnet}/logging/{logType}/stream` | `getLogStreamingConfiguration` | tool: `tailscale_get_log_streaming_configuration` | `tool:tailscale_get_log_streaming_configuration` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | PUT | `/tailnet/{tailnet}/logging/{logType}/stream` | `setLogStreamingConfiguration` | tool: `tailscale_set_log_streaming_configuration` | `tool:tailscale_set_log_streaming_configuration` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/tailnet/{tailnet}/logging/{logType}/stream/status` | `getLogStreamingStatus` | tool: `tailscale_get_log_streaming_status` | `tool:tailscale_get_log_streaming_status` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |

## OAuthApps

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | GET | `/tailnet/{tailnet}/oauth-apps` | `listOAuthApps` | resource: `tailscale://oauth-apps` | `resource:tailscale://oauth-apps` | Stable tailnet state is exposed as an MCP JSON resource through the generic read API resource registrar. |
| implemented | POST | `/tailnet/{tailnet}/oauth-apps` | `createOAuthApp` | tool: `tailscale_create_oauth_app` | `tool:tailscale_create_oauth_app` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | DELETE | `/tailnet/{tailnet}/oauth-apps/{appId}` | `deleteOAuthApp` | tool: `tailscale_delete_oauth_app` | `tool:tailscale_delete_oauth_app` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/tailnet/{tailnet}/oauth-apps/{appId}` | `getOAuthApp` | tool: `tailscale_get_oauth_app` | `tool:tailscale_get_oauth_app` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | PUT | `/tailnet/{tailnet}/oauth-apps/{appId}` | `updateOAuthApp` | tool: `tailscale_update_oauth_app` | `tool:tailscale_update_oauth_app` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |

## PolicyFile

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | GET | `/tailnet/{tailnet}/acl` | `getPolicyFile` | resource: `tailscale://policy` | `resource:tailscale://policy` | Policy file is stable tailnet state exposed as JSON. |
| implemented | POST | `/tailnet/{tailnet}/acl` | `setPolicyFile` | tool: `tailscale_set_policy_file` | `tool:tailscale_set_policy_file` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/tailnet/{tailnet}/acl/preview` | `previewRuleMatches` | tool: `tailscale_preview_rule_matches` | `tool:tailscale_preview_rule_matches` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | POST | `/tailnet/{tailnet}/acl/validate` | `validateAndTestPolicyFile` | tool: `tailscale_validate_and_test_policy_file` | `tool:tailscale_validate_and_test_policy_file` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |

## Services

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | GET | `/tailnet/{tailnet}/services` | `listServices` | resource: `tailscale://services` | `resource:tailscale://services` | Stable tailnet state is exposed as an MCP JSON resource through the generic read API resource registrar. |
| implemented | DELETE | `/tailnet/{tailnet}/services/{serviceName}` | `deleteService` | tool: `tailscale_delete_service` | `tool:tailscale_delete_service` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/tailnet/{tailnet}/services/{serviceName}` | `getService` | tool: `tailscale_get_service` | `tool:tailscale_get_service` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | PUT | `/tailnet/{tailnet}/services/{serviceName}` | `updateService` | tool: `tailscale_update_service` | `tool:tailscale_update_service` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved` | `getServiceDeviceApproval` | tool: `tailscale_get_service_device_approval` | `tool:tailscale_get_service_device_approval` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | POST | `/tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved` | `updateServiceDeviceApproval` | tool: `tailscale_update_service_device_approval` | `tool:tailscale_update_service_device_approval` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/tailnet/{tailnet}/services/{serviceName}/devices` | `listServiceHosts` | tool: `tailscale_list_service_hosts` | `tool:tailscale_list_service_hosts` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |

## TailnetSettings

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | GET | `/tailnet/{tailnet}/settings` | `getTailnetSettings` | resource: `tailscale://tailnet-settings` | `resource:tailscale://tailnet-settings` | Tailnet settings are stable tailnet state exposed as JSON. |
| implemented | PATCH | `/tailnet/{tailnet}/settings` | `updateTailnetSettings` | tool: `tailscale_update_tailnet_settings` | `tool:tailscale_update_tailnet_settings` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |

## UserInvites

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | GET | `/tailnet/{tailnet}/user-invites` | `listUserInvites` | resource: `tailscale://user-invites` | `resource:tailscale://user-invites` | Stable tailnet state is exposed as an MCP JSON resource through the generic read API resource registrar. |
| implemented | POST | `/tailnet/{tailnet}/user-invites` | `createUserInvites` | tool: `tailscale_create_user_invites` | `tool:tailscale_create_user_invites` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | DELETE | `/user-invites/{userInviteId}` | `deleteUserInvite` | tool: `tailscale_delete_user_invite` | `tool:tailscale_delete_user_invite` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/user-invites/{userInviteId}` | `getUserInvite` | tool: `tailscale_get_user_invite` | `tool:tailscale_get_user_invite` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | POST | `/user-invites/{userInviteId}/resend` | `resendUserInvite` | tool: `tailscale_resend_user_invite` | `tool:tailscale_resend_user_invite` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |

## Users

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | GET | `/tailnet/{tailnet}/users` | `listUsers` | tool: `tailscale_list_users` | `tool:tailscale_list_users` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | GET | `/users/{userId}` | `getUser` | tool: `tailscale_get_user` | `tool:tailscale_get_user` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | POST | `/users/{userId}/approve` | `approveUser` | tool: `tailscale_approve_user` | `tool:tailscale_approve_user` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/users/{userId}/delete` | `deleteUser` | tool: `tailscale_delete_user` | `tool:tailscale_delete_user` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/users/{userId}/restore` | `restoreUser` | tool: `tailscale_restore_user` | `tool:tailscale_restore_user` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/users/{userId}/role` | `updateUserRole` | tool: `tailscale_update_user_role` | `tool:tailscale_update_user_role` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/users/{userId}/suspend` | `suspendUser` | tool: `tailscale_suspend_user` | `tool:tailscale_suspend_user` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |

## Webhooks

| Status | Method | Path | Operation | MCP | Grant | Rationale |
|---|---|---|---|---|---|---|
| implemented | GET | `/tailnet/{tailnet}/webhooks` | `listWebhooks` | resource: `tailscale://webhooks` | `resource:tailscale://webhooks` | Stable tailnet state is exposed as an MCP JSON resource through the generic read API resource registrar. |
| implemented | POST | `/tailnet/{tailnet}/webhooks` | `createWebhook` | tool: `tailscale_create_webhook` | `tool:tailscale_create_webhook` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | DELETE | `/webhooks/{endpointId}` | `deleteWebhook` | tool: `tailscale_delete_webhook` | `tool:tailscale_delete_webhook` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | GET | `/webhooks/{endpointId}` | `getWebhook` | tool: `tailscale_get_webhook` | `tool:tailscale_get_webhook` | Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar. |
| implemented | PATCH | `/webhooks/{endpointId}` | `updateWebhook` | tool: `tailscale_update_webhook` | `tool:tailscale_update_webhook` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/webhooks/{endpointId}/rotate` | `rotateWebhookSecret` | tool: `tailscale_rotate_webhook_secret` | `tool:tailscale_rotate_webhook_secret` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |
| implemented | POST | `/webhooks/{endpointId}/test` | `testWebhook` | tool: `tailscale_test_webhook` | `tool:tailscale_test_webhook` | Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token. |

