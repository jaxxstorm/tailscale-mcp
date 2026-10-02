package readapi

import "testing"

func TestToolMetadataDomains(t *testing.T) {
	groups := map[string]string{
		"listDeviceRoutes": "devices", "getDevicePostureAttributes": "devices",
		"batchUpdateCustomDevicePostureAttributes": "devices", "setDeviceRoutes": "devices",
		"listDeviceInvites": "invites", "getDeviceInvite": "invites", "listUserInvites": "invites",
		"getUserInvite": "invites", "createDeviceInvites": "invites",
		"getDnsConfiguration": "dns", "setDnsConfiguration": "dns",
		"listTailnetKeys": "keys", "createKey": "keys", "getKey": "keys",
		"listConfigurationAuditLogs": "logging", "listNetworkFlowLogs": "logging",
		"getAwsExternalId": "logging", "validateAwsExternalId": "logging",
		"getLogStreamingConfiguration": "logging", "setLogStreamingConfiguration": "logging",
		"previewRuleMatches": "policy", "validateAndTestPolicyFile": "policy", "setPolicyFile": "policy",
		"getPostureIntegrations": "posture", "getPostureIntegration": "posture", "createPostureIntegration": "posture",
		"listUsers": "users", "getUser": "users", "suspendUser": "users",
		"getContacts": "tailnet", "updateTailnetSettings": "tailnet", "updateContact": "tailnet",
		"listServices": "services", "listServiceHosts": "services", "updateServiceDeviceApproval": "services",
		"listWebhooks": "webhooks", "getWebhook": "webhooks", "rotateWebhookSecret": "webhooks",
		"listOAuthApps": "oauth-apps", "createOAuthApp": "oauth-apps",
	}
	for _, endpoint := range ToolEndpoints() {
		if endpoint.ToolGroup() == "" {
			t.Errorf("missing group: %s", endpoint.OperationID)
		}
		if want, ok := groups[endpoint.OperationID]; ok {
			if endpoint.ToolGroup() != want {
				t.Errorf("%s: group=%s, want %s", endpoint.OperationID, endpoint.ToolGroup(), want)
			}
			delete(groups, endpoint.OperationID)
		}
	}
	if len(groups) != 0 {
		t.Errorf("expected operations absent: %v", groups)
	}
	if (Endpoint{Path: "/unclassified/new-api"}).ToolGroup() != "" {
		t.Fatal("new domain was silently classified")
	}
}
