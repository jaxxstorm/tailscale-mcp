package mcpcoverage

func CurrentMappings() []Mapping {
	return []Mapping{
		{
			OperationID:     "listTailnetDevices",
			Type:            MappingTool,
			Name:            "list_all_devices",
			URI:             ResourceURI("devices"),
			GrantPermission: ToolGrant("list_all_devices"),
			Rationale:       "Device collection is exposed as both a Claude-compatible tool and a stable resource.",
		},
		{
			OperationID:     "getDevice",
			Type:            MappingTool,
			Name:            "get_device_info",
			URI:             ResourceURI("device", "{device}"),
			GrantPermission: ToolGrant("get_device_info"),
			Rationale:       "Parameterized device lookup by ID, hostname, or IP is exposed as a typed tool with a matching resource shape.",
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
}
