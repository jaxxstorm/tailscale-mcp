package readapi

import (
	"strings"

	"github.com/jaxxstorm/tailscale-mcp/internal/toolmeta"
)

// ToolGroup follows API domains, not tool-name heuristics. Device subresources
// remain in devices, except share invitations which belong to invites.
func (e Endpoint) ToolGroup() string {
	parts := strings.Split(strings.Trim(e.Path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "tailnet" {
		parts = parts[2:]
	}
	if len(parts) == 0 {
		return ""
	}
	for _, part := range parts {
		if part == "device-invites" || part == "user-invites" {
			return "invites"
		}
	}
	switch parts[0] {
	case "device", "devices", "device-attributes":
		return "devices"
	case "acl":
		return "policy"
	case "settings", "contacts":
		return "tailnet"
	case "aws-external-id", "logging":
		return "logging"
	case "dns", "keys", "posture", "users", "webhooks", "services", "oauth-apps":
		return parts[0]
	default:
		return ""
	}
}

func ToolMetadata() []toolmeta.Tool {
	var tools []toolmeta.Tool
	for _, endpoint := range ToolEndpoints() {
		tools = append(tools, toolmeta.Tool{Name: endpoint.ToolName, Group: endpoint.ToolGroup(), ReadOnly: endpoint.ToolHints().ReadOnly})
	}
	return tools
}
