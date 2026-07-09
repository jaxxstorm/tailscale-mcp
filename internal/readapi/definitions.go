package readapi

func ReadEndpoints() []Endpoint {
	return []Endpoint{
		{OperationID: "listDeviceRoutes", ToolName: "tailscale_list_device_routes", Summary: "List subnet routes advertised and enabled for a device", Method: "GET", Path: "/device/{deviceId}/routes", Parameters: []Parameter{RequiredPath("deviceId", "Device ID")}},
		{OperationID: "getDevicePostureAttributes", ToolName: "tailscale_get_device_posture_attributes", Summary: "Get posture attributes for a device", Method: "GET", Path: "/device/{deviceId}/attributes", Parameters: []Parameter{RequiredPath("deviceId", "Device ID")}},
		{OperationID: "listDeviceInvites", ToolName: "tailscale_list_device_invites", Summary: "List share invites for a device", Method: "GET", Path: "/device/{deviceId}/device-invites", Parameters: []Parameter{RequiredPath("deviceId", "Device ID")}},
		{OperationID: "listUserInvites", ToolName: "tailscale_list_user_invites", Summary: "List open user invites", Method: "GET", Path: "/tailnet/{tailnet}/user-invites"},
		{OperationID: "getUserInvite", ToolName: "tailscale_get_user_invite", Summary: "Get a user invite", Method: "GET", Path: "/user-invites/{userInviteId}", Parameters: []Parameter{RequiredPath("userInviteId", "User invite ID")}},
		{OperationID: "getDeviceInvite", ToolName: "tailscale_get_device_invite", Summary: "Get a device invite", Method: "GET", Path: "/device-invites/{deviceInviteId}", Parameters: []Parameter{RequiredPath("deviceInviteId", "Device invite ID")}},
		{OperationID: "listConfigurationAuditLogs", ToolName: "tailscale_list_configuration_audit_logs", Summary: "List configuration audit logs", Method: "GET", Path: "/tailnet/{tailnet}/logging/configuration", Parameters: []Parameter{Query("start", "RFC3339 start time", true), Query("end", "RFC3339 end time", true), Query("actor", "Actor filters", false), Query("target", "Target filters", false), Query("event", "Event filters", false)}},
		{OperationID: "listNetworkFlowLogs", ToolName: "tailscale_list_network_flow_logs", Summary: "List network flow logs", Method: "GET", Path: "/tailnet/{tailnet}/logging/network", Parameters: []Parameter{Query("start", "RFC3339 start time", true), Query("end", "RFC3339 end time", true)}},
		{OperationID: "getLogStreamingStatus", ToolName: "tailscale_get_log_streaming_status", Summary: "Get log streaming status", Method: "GET", Path: "/tailnet/{tailnet}/logging/{logType}/stream/status", Parameters: []Parameter{RequiredPath("logType", "Log type")}},
		{OperationID: "getLogStreamingConfiguration", ToolName: "tailscale_get_log_streaming_configuration", Summary: "Get log streaming configuration", Method: "GET", Path: "/tailnet/{tailnet}/logging/{logType}/stream", Parameters: []Parameter{RequiredPath("logType", "Log type")}},
		{OperationID: "validateAwsExternalId", ToolName: "tailscale_validate_aws_external_id", Summary: "Validate an AWS external ID IAM role trust policy", Method: "POST", Path: "/tailnet/{tailnet}/aws-external-id/{id}/validate-aws-trust-policy", Parameters: []Parameter{RequiredPath("id", "AWS external ID")}, Body: true, ReadLike: true},
		{OperationID: "listDnsNameservers", ToolName: "tailscale_list_dns_nameservers", Summary: "List DNS nameservers", Method: "GET", Path: "/tailnet/{tailnet}/dns/nameservers"},
		{OperationID: "getDnsPreferences", ToolName: "tailscale_get_dns_preferences", Summary: "Get DNS preferences", Method: "GET", Path: "/tailnet/{tailnet}/dns/preferences"},
		{OperationID: "listDnsSearchPaths", ToolName: "tailscale_list_dns_search_paths", Summary: "List DNS search paths", Method: "GET", Path: "/tailnet/{tailnet}/dns/searchpaths"},
		{OperationID: "getSplitDns", ToolName: "tailscale_get_split_dns", Summary: "Get split DNS settings", Method: "GET", Path: "/tailnet/{tailnet}/dns/split-dns"},
		{OperationID: "getDnsConfiguration", ToolName: "tailscale_get_dns_configuration", Summary: "Get full DNS configuration", Method: "GET", Path: "/tailnet/{tailnet}/dns/configuration"},
		{OperationID: "listTailnetKeys", ToolName: "tailscale_list_tailnet_keys", Summary: "List active keys", Method: "GET", Path: "/tailnet/{tailnet}/keys", Parameters: []Parameter{Query("all", "Include all keys visible to the token", false)}},
		{OperationID: "getKey", ToolName: "tailscale_get_key", Summary: "Get a key", Method: "GET", Path: "/tailnet/{tailnet}/keys/{keyId}", Parameters: []Parameter{RequiredPath("keyId", "Key ID")}},
		{OperationID: "previewRuleMatches", ToolName: "tailscale_preview_rule_matches", Summary: "Preview policy rule matches without saving policy", Method: "POST", Path: "/tailnet/{tailnet}/acl/preview", Parameters: []Parameter{Query("type", "Preview target type: user or ipport", true), Query("previewFor", "User email or IP:port to preview", true)}, Body: true, ReadLike: true},
		{OperationID: "validateAndTestPolicyFile", ToolName: "tailscale_validate_and_test_policy_file", Summary: "Validate or test a policy file without saving it", Method: "POST", Path: "/tailnet/{tailnet}/acl/validate", Body: true, ReadLike: true},
		{OperationID: "getPostureIntegrations", ToolName: "tailscale_get_posture_integrations", Summary: "List posture integrations", Method: "GET", Path: "/tailnet/{tailnet}/posture/integrations"},
		{OperationID: "getPostureIntegration", ToolName: "tailscale_get_posture_integration", Summary: "Get a posture integration", Method: "GET", Path: "/posture/integrations/{id}", Parameters: []Parameter{RequiredPath("id", "Posture integration ID")}},
		{OperationID: "listUsers", ToolName: "tailscale_list_users", Summary: "List users", Method: "GET", Path: "/tailnet/{tailnet}/users", Parameters: []Parameter{Query("type", "User type filter", false), Query("role", "User role filter", false)}},
		{OperationID: "getUser", ToolName: "tailscale_get_user", Summary: "Get a user", Method: "GET", Path: "/users/{userId}", Parameters: []Parameter{RequiredPath("userId", "User ID")}},
		{OperationID: "getContacts", ToolName: "tailscale_get_contacts", Summary: "Get tailnet contacts", Method: "GET", Path: "/tailnet/{tailnet}/contacts"},
		{OperationID: "listWebhooks", ToolName: "tailscale_list_webhooks", Summary: "List webhooks", Method: "GET", Path: "/tailnet/{tailnet}/webhooks"},
		{OperationID: "getWebhook", ToolName: "tailscale_get_webhook", Summary: "Get a webhook", Method: "GET", Path: "/webhooks/{endpointId}", Parameters: []Parameter{RequiredPath("endpointId", "Webhook endpoint ID")}},
		{OperationID: "listServices", ToolName: "tailscale_list_services", Summary: "List services", Method: "GET", Path: "/tailnet/{tailnet}/services"},
		{OperationID: "getService", ToolName: "tailscale_get_service", Summary: "Get a service", Method: "GET", Path: "/tailnet/{tailnet}/services/{serviceName}", Parameters: []Parameter{RequiredPath("serviceName", "Service name")}},
		{OperationID: "listServiceHosts", ToolName: "tailscale_list_service_hosts", Summary: "List devices hosting a service", Method: "GET", Path: "/tailnet/{tailnet}/services/{serviceName}/devices", Parameters: []Parameter{RequiredPath("serviceName", "Service name")}},
		{OperationID: "getServiceDeviceApproval", ToolName: "tailscale_get_service_device_approval", Summary: "Get service approval status for a device", Method: "GET", Path: "/tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved", Parameters: []Parameter{RequiredPath("serviceName", "Service name"), RequiredPath("deviceId", "Device ID")}},
		{OperationID: "listOAuthApps", ToolName: "tailscale_list_oauth_apps", Summary: "List OAuth apps", Method: "GET", Path: "/tailnet/{tailnet}/oauth-apps"},
		{OperationID: "getOAuthApp", ToolName: "tailscale_get_oauth_app", Summary: "Get an OAuth app", Method: "GET", Path: "/tailnet/{tailnet}/oauth-apps/{appId}", Parameters: []Parameter{RequiredPath("appId", "OAuth app ID")}},
	}
}

func MutatingEndpoints() []Endpoint {
	return []Endpoint{
		{OperationID: "updateContact", ToolName: "tailscale_update_contact", Summary: "Update a tailnet contact", Method: "PATCH", Path: "/tailnet/{tailnet}/contacts/{contactType}", Parameters: []Parameter{RequiredPath("contactType", "Contact type")}, Body: true, Confirm: "updateContact"},
		{OperationID: "resendContactVerificationEmail", ToolName: "tailscale_resend_contact_verification_email", Summary: "Resend contact verification email", Method: "POST", Path: "/tailnet/{tailnet}/contacts/{contactType}/resend-verification-email", Parameters: []Parameter{RequiredPath("contactType", "Contact type")}, Confirm: "resendContactVerificationEmail"},
		{OperationID: "setDnsConfiguration", ToolName: "tailscale_set_dns_configuration", Summary: "Replace DNS configuration", Method: "POST", Path: "/tailnet/{tailnet}/dns/configuration", Body: true, Confirm: "setDnsConfiguration"},
		{OperationID: "setDnsNameservers", ToolName: "tailscale_set_dns_nameservers", Summary: "Replace DNS nameservers", Method: "POST", Path: "/tailnet/{tailnet}/dns/nameservers", Body: true, Confirm: "setDnsNameservers"},
		{OperationID: "setDnsPreferences", ToolName: "tailscale_set_dns_preferences", Summary: "Set DNS preferences", Method: "POST", Path: "/tailnet/{tailnet}/dns/preferences", Body: true, Confirm: "setDnsPreferences"},
		{OperationID: "setDnsSearchPaths", ToolName: "tailscale_set_dns_search_paths", Summary: "Replace DNS search paths", Method: "POST", Path: "/tailnet/{tailnet}/dns/searchpaths", Body: true, Confirm: "setDnsSearchPaths"},
		{OperationID: "updateSplitDns", ToolName: "tailscale_update_split_dns", Summary: "Partially update split DNS settings", Method: "PATCH", Path: "/tailnet/{tailnet}/dns/split-dns", Body: true, Confirm: "updateSplitDns"},
		{OperationID: "setSplitDns", ToolName: "tailscale_set_split_dns", Summary: "Replace split DNS settings", Method: "PUT", Path: "/tailnet/{tailnet}/dns/split-dns", Body: true, Confirm: "setSplitDns"},
		{OperationID: "acceptDeviceInvite", ToolName: "tailscale_accept_device_invite", Summary: "Accept a device invite", Method: "POST", Path: "/device-invites/-/accept", Body: true, Confirm: "acceptDeviceInvite"},
		{OperationID: "deleteDeviceInvite", ToolName: "tailscale_delete_device_invite", Summary: "Delete a device invite", Method: "DELETE", Path: "/device-invites/{deviceInviteId}", Parameters: []Parameter{RequiredPath("deviceInviteId", "Device invite ID")}, Confirm: "deleteDeviceInvite"},
		{OperationID: "resendDeviceInvite", ToolName: "tailscale_resend_device_invite", Summary: "Resend a device invite", Method: "POST", Path: "/device-invites/{deviceInviteId}/resend", Parameters: []Parameter{RequiredPath("deviceInviteId", "Device invite ID")}, Confirm: "resendDeviceInvite"},
		{OperationID: "createDeviceInvites", ToolName: "tailscale_create_device_invites", Summary: "Create device invites", Method: "POST", Path: "/device/{deviceId}/device-invites", Parameters: []Parameter{RequiredPath("deviceId", "Device ID")}, Body: true, Confirm: "createDeviceInvites"},
		{OperationID: "deletePostureIntegration", ToolName: "tailscale_delete_posture_integration", Summary: "Delete a posture integration", Method: "DELETE", Path: "/posture/integrations/{id}", Parameters: []Parameter{RequiredPath("id", "Posture integration ID")}, Confirm: "deletePostureIntegration"},
		{OperationID: "updatePostureIntegration", ToolName: "tailscale_update_posture_integration", Summary: "Update a posture integration", Method: "PATCH", Path: "/posture/integrations/{id}", Parameters: []Parameter{RequiredPath("id", "Posture integration ID")}, Body: true, Confirm: "updatePostureIntegration"},
		{OperationID: "createPostureIntegration", ToolName: "tailscale_create_posture_integration", Summary: "Create a posture integration", Method: "POST", Path: "/tailnet/{tailnet}/posture/integrations", Body: true, Confirm: "createPostureIntegration"},
		{OperationID: "deleteDevice", ToolName: "tailscale_delete_device", Summary: "Delete a device", Method: "DELETE", Path: "/device/{deviceId}", Parameters: []Parameter{RequiredPath("deviceId", "Device ID")}, Confirm: "deleteDevice"},
		{OperationID: "deleteCustomDevicePostureAttributes", ToolName: "tailscale_delete_custom_device_posture_attributes", Summary: "Delete a custom device posture attribute", Method: "DELETE", Path: "/device/{deviceId}/attributes/{attributeKey}", Parameters: []Parameter{RequiredPath("deviceId", "Device ID"), RequiredPath("attributeKey", "Attribute key")}, Confirm: "deleteCustomDevicePostureAttributes"},
		{OperationID: "setCustomDevicePostureAttributes", ToolName: "tailscale_set_custom_device_posture_attributes", Summary: "Set a custom device posture attribute", Method: "POST", Path: "/device/{deviceId}/attributes/{attributeKey}", Parameters: []Parameter{RequiredPath("deviceId", "Device ID"), RequiredPath("attributeKey", "Attribute key")}, Body: true, Confirm: "setCustomDevicePostureAttributes"},
		{OperationID: "authorizeDevice", ToolName: "tailscale_authorize_device", Summary: "Authorize or deauthorize a device", Method: "POST", Path: "/device/{deviceId}/authorized", Parameters: []Parameter{RequiredPath("deviceId", "Device ID")}, Body: true, Confirm: "authorizeDevice"},
		{OperationID: "expireDeviceKey", ToolName: "tailscale_expire_device_key", Summary: "Expire a device key", Method: "POST", Path: "/device/{deviceId}/expire", Parameters: []Parameter{RequiredPath("deviceId", "Device ID")}, Confirm: "expireDeviceKey"},
		{OperationID: "setDeviceIp", ToolName: "tailscale_set_device_ip", Summary: "Set a device IPv4 address", Method: "POST", Path: "/device/{deviceId}/ip", Parameters: []Parameter{RequiredPath("deviceId", "Device ID")}, Body: true, Confirm: "setDeviceIp"},
		{OperationID: "updateDeviceKey", ToolName: "tailscale_update_device_key", Summary: "Update device key expiry setting", Method: "POST", Path: "/device/{deviceId}/key", Parameters: []Parameter{RequiredPath("deviceId", "Device ID")}, Body: true, Confirm: "updateDeviceKey"},
		{OperationID: "setDeviceName", ToolName: "tailscale_set_device_name", Summary: "Set device name", Method: "POST", Path: "/device/{deviceId}/name", Parameters: []Parameter{RequiredPath("deviceId", "Device ID")}, Body: true, Confirm: "setDeviceName"},
		{OperationID: "setDeviceRoutes", ToolName: "tailscale_set_device_routes", Summary: "Set enabled device routes", Method: "POST", Path: "/device/{deviceId}/routes", Parameters: []Parameter{RequiredPath("deviceId", "Device ID")}, Body: true, Confirm: "setDeviceRoutes"},
		{OperationID: "setDeviceTags", ToolName: "tailscale_set_device_tags", Summary: "Set device tags", Method: "POST", Path: "/device/{deviceId}/tags", Parameters: []Parameter{RequiredPath("deviceId", "Device ID")}, Body: true, Confirm: "setDeviceTags"},
		{OperationID: "batchUpdateCustomDevicePostureAttributes", ToolName: "tailscale_batch_update_custom_device_posture_attributes", Summary: "Batch update custom device posture attributes", Method: "PATCH", Path: "/tailnet/{tailnet}/device-attributes", Body: true, Confirm: "batchUpdateCustomDevicePostureAttributes"},
		{OperationID: "createKey", ToolName: "tailscale_create_key", Summary: "Create an auth key or trust credential", Method: "POST", Path: "/tailnet/{tailnet}/keys", Body: true, Confirm: "createKey"},
		{OperationID: "deleteKey", ToolName: "tailscale_delete_key", Summary: "Delete a key", Method: "DELETE", Path: "/tailnet/{tailnet}/keys/{keyId}", Parameters: []Parameter{RequiredPath("keyId", "Key ID")}, Confirm: "deleteKey"},
		{OperationID: "setKey", ToolName: "tailscale_set_key", Summary: "Set key configuration", Method: "PUT", Path: "/tailnet/{tailnet}/keys/{keyId}", Parameters: []Parameter{RequiredPath("keyId", "Key ID")}, Body: true, Confirm: "setKey"},
		{OperationID: "getAwsExternalId", ToolName: "tailscale_get_aws_external_id", Summary: "Create or get an AWS external ID for log streaming", Method: "POST", Path: "/tailnet/{tailnet}/aws-external-id", Body: true, Confirm: "getAwsExternalId"},
		{OperationID: "disableLogStreaming", ToolName: "tailscale_disable_log_streaming", Summary: "Disable log streaming", Method: "DELETE", Path: "/tailnet/{tailnet}/logging/{logType}/stream", Parameters: []Parameter{RequiredPath("logType", "Log type")}, Confirm: "disableLogStreaming"},
		{OperationID: "setLogStreamingConfiguration", ToolName: "tailscale_set_log_streaming_configuration", Summary: "Set log streaming configuration", Method: "PUT", Path: "/tailnet/{tailnet}/logging/{logType}/stream", Parameters: []Parameter{RequiredPath("logType", "Log type")}, Body: true, Confirm: "setLogStreamingConfiguration"},
		{OperationID: "createOAuthApp", ToolName: "tailscale_create_oauth_app", Summary: "Create an OAuth app", Method: "POST", Path: "/tailnet/{tailnet}/oauth-apps", Body: true, Confirm: "createOAuthApp"},
		{OperationID: "deleteOAuthApp", ToolName: "tailscale_delete_oauth_app", Summary: "Delete an OAuth app", Method: "DELETE", Path: "/tailnet/{tailnet}/oauth-apps/{appId}", Parameters: []Parameter{RequiredPath("appId", "OAuth app ID")}, Confirm: "deleteOAuthApp"},
		{OperationID: "updateOAuthApp", ToolName: "tailscale_update_oauth_app", Summary: "Update an OAuth app", Method: "PUT", Path: "/tailnet/{tailnet}/oauth-apps/{appId}", Parameters: []Parameter{RequiredPath("appId", "OAuth app ID")}, Body: true, Confirm: "updateOAuthApp"},
		{OperationID: "setPolicyFile", ToolName: "tailscale_set_policy_file", Summary: "Set the tailnet policy file", Method: "POST", Path: "/tailnet/{tailnet}/acl", Body: true, Confirm: "setPolicyFile"},
		{OperationID: "deleteService", ToolName: "tailscale_delete_service", Summary: "Delete a service", Method: "DELETE", Path: "/tailnet/{tailnet}/services/{serviceName}", Parameters: []Parameter{RequiredPath("serviceName", "Service name")}, Confirm: "deleteService"},
		{OperationID: "updateService", ToolName: "tailscale_update_service", Summary: "Update or create a service", Method: "PUT", Path: "/tailnet/{tailnet}/services/{serviceName}", Parameters: []Parameter{RequiredPath("serviceName", "Service name")}, Body: true, Confirm: "updateService"},
		{OperationID: "updateServiceDeviceApproval", ToolName: "tailscale_update_service_device_approval", Summary: "Update service approval on a device", Method: "POST", Path: "/tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved", Parameters: []Parameter{RequiredPath("serviceName", "Service name"), RequiredPath("deviceId", "Device ID")}, Body: true, Confirm: "updateServiceDeviceApproval"},
		{OperationID: "updateTailnetSettings", ToolName: "tailscale_update_tailnet_settings", Summary: "Update tailnet settings", Method: "PATCH", Path: "/tailnet/{tailnet}/settings", Body: true, Confirm: "updateTailnetSettings"},
		{OperationID: "createUserInvites", ToolName: "tailscale_create_user_invites", Summary: "Create user invites", Method: "POST", Path: "/tailnet/{tailnet}/user-invites", Body: true, Confirm: "createUserInvites"},
		{OperationID: "deleteUserInvite", ToolName: "tailscale_delete_user_invite", Summary: "Delete a user invite", Method: "DELETE", Path: "/user-invites/{userInviteId}", Parameters: []Parameter{RequiredPath("userInviteId", "User invite ID")}, Confirm: "deleteUserInvite"},
		{OperationID: "resendUserInvite", ToolName: "tailscale_resend_user_invite", Summary: "Resend a user invite", Method: "POST", Path: "/user-invites/{userInviteId}/resend", Parameters: []Parameter{RequiredPath("userInviteId", "User invite ID")}, Confirm: "resendUserInvite"},
		{OperationID: "approveUser", ToolName: "tailscale_approve_user", Summary: "Approve a user", Method: "POST", Path: "/users/{userId}/approve", Parameters: []Parameter{RequiredPath("userId", "User ID")}, Confirm: "approveUser"},
		{OperationID: "deleteUser", ToolName: "tailscale_delete_user", Summary: "Delete a user", Method: "POST", Path: "/users/{userId}/delete", Parameters: []Parameter{RequiredPath("userId", "User ID")}, Confirm: "deleteUser"},
		{OperationID: "restoreUser", ToolName: "tailscale_restore_user", Summary: "Restore a user", Method: "POST", Path: "/users/{userId}/restore", Parameters: []Parameter{RequiredPath("userId", "User ID")}, Confirm: "restoreUser"},
		{OperationID: "updateUserRole", ToolName: "tailscale_update_user_role", Summary: "Update a user role", Method: "POST", Path: "/users/{userId}/role", Parameters: []Parameter{RequiredPath("userId", "User ID")}, Body: true, Confirm: "updateUserRole"},
		{OperationID: "suspendUser", ToolName: "tailscale_suspend_user", Summary: "Suspend a user", Method: "POST", Path: "/users/{userId}/suspend", Parameters: []Parameter{RequiredPath("userId", "User ID")}, Confirm: "suspendUser"},
		{OperationID: "createWebhook", ToolName: "tailscale_create_webhook", Summary: "Create a webhook", Method: "POST", Path: "/tailnet/{tailnet}/webhooks", Body: true, Confirm: "createWebhook"},
		{OperationID: "deleteWebhook", ToolName: "tailscale_delete_webhook", Summary: "Delete a webhook", Method: "DELETE", Path: "/webhooks/{endpointId}", Parameters: []Parameter{RequiredPath("endpointId", "Webhook endpoint ID")}, Confirm: "deleteWebhook"},
		{OperationID: "updateWebhook", ToolName: "tailscale_update_webhook", Summary: "Update a webhook", Method: "PATCH", Path: "/webhooks/{endpointId}", Parameters: []Parameter{RequiredPath("endpointId", "Webhook endpoint ID")}, Body: true, Confirm: "updateWebhook"},
		{OperationID: "rotateWebhookSecret", ToolName: "tailscale_rotate_webhook_secret", Summary: "Rotate a webhook secret", Method: "POST", Path: "/webhooks/{endpointId}/rotate", Parameters: []Parameter{RequiredPath("endpointId", "Webhook endpoint ID")}, Confirm: "rotateWebhookSecret"},
		{OperationID: "testWebhook", ToolName: "tailscale_test_webhook", Summary: "Send a test webhook event", Method: "POST", Path: "/webhooks/{endpointId}/test", Parameters: []Parameter{RequiredPath("endpointId", "Webhook endpoint ID")}, Confirm: "testWebhook"},
	}
}

func ToolEndpoints() []Endpoint {
	endpoints := ReadEndpoints()
	endpoints = append(endpoints, MutatingEndpoints()...)
	return endpoints
}

func Resources() []Resource {
	byOperation := map[string]Endpoint{}
	for _, endpoint := range ReadEndpoints() {
		byOperation[endpoint.OperationID] = endpoint
	}
	return []Resource{
		{OperationID: "listDnsNameservers", URI: "tailscale://dns/nameservers", Name: "DNS nameservers", Endpoint: byOperation["listDnsNameservers"]},
		{OperationID: "getDnsPreferences", URI: "tailscale://dns/preferences", Name: "DNS preferences", Endpoint: byOperation["getDnsPreferences"]},
		{OperationID: "listDnsSearchPaths", URI: "tailscale://dns/searchpaths", Name: "DNS search paths", Endpoint: byOperation["listDnsSearchPaths"]},
		{OperationID: "getSplitDns", URI: "tailscale://dns/split-dns", Name: "Split DNS", Endpoint: byOperation["getSplitDns"]},
		{OperationID: "getDnsConfiguration", URI: "tailscale://dns/configuration", Name: "DNS configuration", Endpoint: byOperation["getDnsConfiguration"]},
		{OperationID: "listUserInvites", URI: "tailscale://user-invites", Name: "User invites", Endpoint: byOperation["listUserInvites"]},
		{OperationID: "listTailnetKeys", URI: "tailscale://keys", Name: "Keys", Endpoint: byOperation["listTailnetKeys"]},
		{OperationID: "listWebhooks", URI: "tailscale://webhooks", Name: "Webhooks", Endpoint: byOperation["listWebhooks"]},
		{OperationID: "listServices", URI: "tailscale://services", Name: "Services", Endpoint: byOperation["listServices"]},
		{OperationID: "getPostureIntegrations", URI: "tailscale://posture/integrations", Name: "Posture integrations", Endpoint: byOperation["getPostureIntegrations"]},
		{OperationID: "listOAuthApps", URI: "tailscale://oauth-apps", Name: "OAuth apps", Endpoint: byOperation["listOAuthApps"]},
	}
}

func ResourceTemplates() []ResourceTemplate {
	byOperation := map[string]Endpoint{}
	for _, endpoint := range ReadEndpoints() {
		byOperation[endpoint.OperationID] = endpoint
	}
	return []ResourceTemplate{
		{OperationID: "listDeviceRoutes", URI: "tailscale://device/{deviceId}/routes", Name: "Device routes", Endpoint: byOperation["listDeviceRoutes"]},
		{OperationID: "getDevicePostureAttributes", URI: "tailscale://device/{deviceId}/attributes", Name: "Device posture attributes", Endpoint: byOperation["getDevicePostureAttributes"]},
	}
}
