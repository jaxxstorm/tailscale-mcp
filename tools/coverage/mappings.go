package mcpcoverage

import "github.com/jaxxstorm/tailscale-mcp/internal/readapi"

func CurrentMappings() []Mapping {
	mappings := []Mapping{
		{
			OperationID:     "listTailnetDevices",
			Type:            MappingTool,
			Name:            "list_all_devices",
			URI:             ResourceURI("devices"),
			GrantPermission: ToolGrant("list_all_devices"),
			Rationale:       "Device collection is exposed as both a Claude-compatible tool and a stable resource.",
			ReadOnly:        true,
			Idempotent:      true,
		},
		{
			OperationID:     "getDevice",
			Type:            MappingTool,
			Name:            "get_device_info",
			URI:             ResourceURI("device", "{device}"),
			GrantPermission: ToolGrant("get_device_info"),
			Rationale:       "Parameterized device lookup by ID, hostname, or IP is exposed as a typed tool with a matching resource shape.",
			ReadOnly:        true,
			Idempotent:      true,
		},
		{
			OperationID:     "getPolicyFile",
			Type:            MappingResource,
			URI:             ResourceURI("policy"),
			GrantPermission: ResourceGrant(ResourceURI("policy")),
			Rationale:       "Policy file is stable tailnet state exposed as JSON.",
		},
		{
			OperationID:     "getTailnetSettings",
			Type:            MappingResource,
			URI:             ResourceURI("tailnet-settings"),
			GrantPermission: ResourceGrant(ResourceURI("tailnet-settings")),
			Rationale:       "Tailnet settings are stable tailnet state exposed as JSON.",
		},
	}

	for _, endpoint := range readapi.ToolEndpoints() {
		hints := endpoint.ToolHints()
		rationale := "Read-only Tailscale Admin API operation is exposed through the generic read API tool registrar."
		if endpoint.OperationID == "listNetworkFlowLogs" {
			rationale = "Network flow logs are exposed through a bounded, cursor-based MCP tool to keep responses within client context limits."
		}
		if endpoint.Confirm != "" {
			rationale = "Tailscale Admin API operation is exposed as a guarded MCP tool that requires an explicit confirmation token."
		}
		mappings = append(mappings, Mapping{
			OperationID:     endpoint.OperationID,
			Type:            MappingTool,
			Name:            endpoint.ToolName,
			GrantPermission: ToolGrant(endpoint.ToolName),
			Rationale:       rationale,
			ReadOnly:        hints.ReadOnly,
			Destructive:     hints.Destructive,
			Idempotent:      hints.Idempotent,
			Confirmation:    endpoint.Confirm,
		})
	}
	for _, resource := range readapi.Resources() {
		mappings = append(mappings, Mapping{
			OperationID:     resource.OperationID,
			Type:            MappingResource,
			URI:             resource.URI,
			GrantPermission: ResourceGrant(resource.URI),
			Rationale:       "Stable tailnet state is exposed as an MCP JSON resource through the generic read API resource registrar.",
		})
	}
	for _, resource := range readapi.ResourceTemplates() {
		mappings = append(mappings, Mapping{
			OperationID:     resource.OperationID,
			Type:            MappingResource,
			URI:             resource.URI,
			GrantPermission: ResourceGrant(resource.URI),
			Rationale:       "Parameterized device state is exposed as an MCP JSON resource template through the generic read API resource registrar.",
		})
	}

	return mappings
}
