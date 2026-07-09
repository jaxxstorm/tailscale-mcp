# MCP Parity Backlog

Unimplemented Tailscale OpenAPI operations grouped by domain.

## Contacts

- [ ] `GET /tailnet/{tailnet}/contacts` (`getContacts`) -> tool
- [ ] `PATCH /tailnet/{tailnet}/contacts/{contactType}` (`updateContact`) -> tool
- [ ] `POST /tailnet/{tailnet}/contacts/{contactType}/resend-verification-email` (`resendContactVerificationEmail`) -> tool

## DNS

- [ ] `GET /tailnet/{tailnet}/dns/configuration` (`getDnsConfiguration`) -> tool
- [ ] `POST /tailnet/{tailnet}/dns/configuration` (`setDnsConfiguration`) -> tool
- [ ] `GET /tailnet/{tailnet}/dns/nameservers` (`listDnsNameservers`) -> tool
- [ ] `POST /tailnet/{tailnet}/dns/nameservers` (`setDnsNameservers`) -> tool
- [ ] `GET /tailnet/{tailnet}/dns/preferences` (`getDnsPreferences`) -> tool
- [ ] `POST /tailnet/{tailnet}/dns/preferences` (`setDnsPreferences`) -> tool
- [ ] `GET /tailnet/{tailnet}/dns/searchpaths` (`listDnsSearchPaths`) -> tool
- [ ] `POST /tailnet/{tailnet}/dns/searchpaths` (`setDnsSearchPaths`) -> tool
- [ ] `GET /tailnet/{tailnet}/dns/split-dns` (`getSplitDns`) -> tool
- [ ] `PATCH /tailnet/{tailnet}/dns/split-dns` (`updateSplitDns`) -> tool
- [ ] `PUT /tailnet/{tailnet}/dns/split-dns` (`setSplitDns`) -> tool

## DeviceInvites

- [ ] `POST /device-invites/-/accept` (`acceptDeviceInvite`) -> tool
- [ ] `DELETE /device-invites/{deviceInviteId}` (`deleteDeviceInvite`) -> tool
- [ ] `GET /device-invites/{deviceInviteId}` (`getDeviceInvite`) -> tool
- [ ] `POST /device-invites/{deviceInviteId}/resend` (`resendDeviceInvite`) -> tool
- [ ] `GET /device/{deviceId}/device-invites` (`listDeviceInvites`) -> tool
- [ ] `POST /device/{deviceId}/device-invites` (`createDeviceInvites`) -> tool

## DevicePosture

- [ ] `DELETE /posture/integrations/{id}` (`deletePostureIntegration`) -> tool
- [ ] `GET /posture/integrations/{id}` (`getPostureIntegration`) -> tool
- [ ] `PATCH /posture/integrations/{id}` (`updatePostureIntegration`) -> tool
- [ ] `GET /tailnet/{tailnet}/posture/integrations` (`getPostureIntegrations`) -> tool
- [ ] `POST /tailnet/{tailnet}/posture/integrations` (`createPostureIntegration`) -> tool

## Devices

- [ ] `DELETE /device/{deviceId}` (`deleteDevice`) -> tool
- [ ] `GET /device/{deviceId}/attributes` (`getDevicePostureAttributes`) -> tool
- [ ] `DELETE /device/{deviceId}/attributes/{attributeKey}` (`deleteCustomDevicePostureAttributes`) -> tool
- [ ] `POST /device/{deviceId}/attributes/{attributeKey}` (`setCustomDevicePostureAttributes`) -> tool
- [ ] `POST /device/{deviceId}/authorized` (`authorizeDevice`) -> tool
- [ ] `POST /device/{deviceId}/expire` (`expireDeviceKey`) -> tool
- [ ] `POST /device/{deviceId}/ip` (`setDeviceIp`) -> tool
- [ ] `POST /device/{deviceId}/key` (`updateDeviceKey`) -> tool
- [ ] `POST /device/{deviceId}/name` (`setDeviceName`) -> tool
- [ ] `GET /device/{deviceId}/routes` (`listDeviceRoutes`) -> tool
- [ ] `POST /device/{deviceId}/routes` (`setDeviceRoutes`) -> tool
- [ ] `POST /device/{deviceId}/tags` (`setDeviceTags`) -> tool
- [ ] `PATCH /tailnet/{tailnet}/device-attributes` (`batchUpdateCustomDevicePostureAttributes`) -> tool

## Keys

- [ ] `GET /tailnet/{tailnet}/keys` (`listTailnetKeys`) -> tool
- [ ] `POST /tailnet/{tailnet}/keys` (`createKey`) -> tool
- [ ] `DELETE /tailnet/{tailnet}/keys/{keyId}` (`deleteKey`) -> tool
- [ ] `GET /tailnet/{tailnet}/keys/{keyId}` (`getKey`) -> tool
- [ ] `PUT /tailnet/{tailnet}/keys/{keyId}` (`setKey`) -> tool

## Logging

- [ ] `POST /tailnet/{tailnet}/aws-external-id` (`getAwsExternalId`) -> tool
- [ ] `POST /tailnet/{tailnet}/aws-external-id/{id}/validate-aws-trust-policy` (`validateAwsExternalId`) -> tool
- [ ] `GET /tailnet/{tailnet}/logging/configuration` (`listConfigurationAuditLogs`) -> tool
- [ ] `GET /tailnet/{tailnet}/logging/network` (`listNetworkFlowLogs`) -> tool
- [ ] `DELETE /tailnet/{tailnet}/logging/{logType}/stream` (`disableLogStreaming`) -> tool
- [ ] `GET /tailnet/{tailnet}/logging/{logType}/stream` (`getLogStreamingConfiguration`) -> tool
- [ ] `PUT /tailnet/{tailnet}/logging/{logType}/stream` (`setLogStreamingConfiguration`) -> tool
- [ ] `GET /tailnet/{tailnet}/logging/{logType}/stream/status` (`getLogStreamingStatus`) -> tool

## OAuthApps

- [ ] `GET /tailnet/{tailnet}/oauth-apps` (`listOAuthApps`) -> tool
- [ ] `POST /tailnet/{tailnet}/oauth-apps` (`createOAuthApp`) -> tool
- [ ] `DELETE /tailnet/{tailnet}/oauth-apps/{appId}` (`deleteOAuthApp`) -> tool
- [ ] `GET /tailnet/{tailnet}/oauth-apps/{appId}` (`getOAuthApp`) -> tool
- [ ] `PUT /tailnet/{tailnet}/oauth-apps/{appId}` (`updateOAuthApp`) -> tool

## PolicyFile

- [ ] `POST /tailnet/{tailnet}/acl` (`setPolicyFile`) -> tool
- [ ] `POST /tailnet/{tailnet}/acl/preview` (`previewRuleMatches`) -> tool
- [ ] `POST /tailnet/{tailnet}/acl/validate` (`validateAndTestPolicyFile`) -> tool

## Services

- [ ] `GET /tailnet/{tailnet}/services` (`listServices`) -> tool
- [ ] `DELETE /tailnet/{tailnet}/services/{serviceName}` (`deleteService`) -> tool
- [ ] `GET /tailnet/{tailnet}/services/{serviceName}` (`getService`) -> tool
- [ ] `PUT /tailnet/{tailnet}/services/{serviceName}` (`updateService`) -> tool
- [ ] `GET /tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved` (`getServiceDeviceApproval`) -> tool
- [ ] `POST /tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved` (`updateServiceDeviceApproval`) -> tool
- [ ] `GET /tailnet/{tailnet}/services/{serviceName}/devices` (`listServiceHosts`) -> tool

## TailnetSettings

- [ ] `PATCH /tailnet/{tailnet}/settings` (`updateTailnetSettings`) -> tool

## UserInvites

- [ ] `GET /tailnet/{tailnet}/user-invites` (`listUserInvites`) -> tool
- [ ] `POST /tailnet/{tailnet}/user-invites` (`createUserInvites`) -> tool
- [ ] `DELETE /user-invites/{userInviteId}` (`deleteUserInvite`) -> tool
- [ ] `GET /user-invites/{userInviteId}` (`getUserInvite`) -> tool
- [ ] `POST /user-invites/{userInviteId}/resend` (`resendUserInvite`) -> tool

## Users

- [ ] `GET /tailnet/{tailnet}/users` (`listUsers`) -> tool
- [ ] `GET /users/{userId}` (`getUser`) -> tool
- [ ] `POST /users/{userId}/approve` (`approveUser`) -> tool
- [ ] `POST /users/{userId}/delete` (`deleteUser`) -> tool
- [ ] `POST /users/{userId}/restore` (`restoreUser`) -> tool
- [ ] `POST /users/{userId}/role` (`updateUserRole`) -> tool
- [ ] `POST /users/{userId}/suspend` (`suspendUser`) -> tool

## Webhooks

- [ ] `GET /tailnet/{tailnet}/webhooks` (`listWebhooks`) -> tool
- [ ] `POST /tailnet/{tailnet}/webhooks` (`createWebhook`) -> tool
- [ ] `DELETE /webhooks/{endpointId}` (`deleteWebhook`) -> tool
- [ ] `GET /webhooks/{endpointId}` (`getWebhook`) -> tool
- [ ] `PATCH /webhooks/{endpointId}` (`updateWebhook`) -> tool
- [ ] `POST /webhooks/{endpointId}/rotate` (`rotateWebhookSecret`) -> tool
- [ ] `POST /webhooks/{endpointId}/test` (`testWebhook`) -> tool

