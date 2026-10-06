package aperture

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jaxxstorm/tailscale-mcp/internal/toolmeta"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Operation is the explicit offline mapping to the cached OpenAPI contract.
type Operation struct {
	OperationID string
	Method      string
	Path        string
	ToolName    string
	Group       string
	ReadOnly    bool
}

// Operations returns an independent copy of the reviewed operation mappings.
func Operations() []Operation {
	return []Operation{
		{"get-config", "GET", "/config", "aperture_get_config", "aperture-config", true},
		{"validate-config", "POST", "/config:validate", "aperture_validate_config", "aperture-config", true},
		{"set-config", "PUT", "/config", "aperture_set_config", "aperture-config", false},
		{"get-pricing", "GET", "/pricing", "aperture_get_pricing", "aperture-pricing", true},
		{"get-model-pricing", "GET", "/pricing/{model}", "aperture_get_model_pricing", "aperture-pricing", true},
	}
}

func ToolMetadata() []toolmeta.Tool {
	tools := make([]toolmeta.Tool, 0, 5)
	for _, op := range Operations() {
		tools = append(tools, toolmeta.Tool{Name: op.ToolName, Group: op.Group, ReadOnly: op.ReadOnly})
	}
	return tools
}

func requiredInputs(name string) []string {
	switch name {
	case "aperture_validate_config":
		return []string{"config"}
	case "aperture_set_config":
		return []string{"config", "if_match", "confirm"}
	case "aperture_get_model_pricing":
		return []string{"model"}
	default:
		return nil
	}
}

// RegisterTools is offline-safe. A nil access checker fails closed.
func RegisterTools(s *server.MCPServer, client Client, check func(context.Context, string) error) {
	descriptions := map[string]string{
		"aperture_get_config":        "Read backend-redacted HuJSON configuration and its ETag. Requires upstream admin. Redacted provider keys are not guaranteed safe to write back unchanged.",
		"aperture_validate_config":   "Validate HuJSON configuration without saving. Requires upstream admin. Configuration inputs may contain provider secrets; diagnostics are sanitized.",
		"aperture_set_config":        "Destructive full configuration replacement, not a merge. Requires upstream admin, confirm=aperture_set_config, and a concrete if_match ETag from a prior read. Inputs may contain provider secrets. Redacted provider keys are not guaranteed safe to write back unchanged; supply a valid full replacement with appropriate key handling. Conflicts are not retried.",
		"aperture_get_pricing":       "Read the complete pricing catalog including units, cost bases and configured adjustments. Requires upstream read_pricing: true; admin alone is insufficient. No model-access filtering or pagination.",
		"aperture_get_model_pricing": "Read pricing for one exact model, including slash-separated identifiers. Empty models is a successful result. Requires upstream read_pricing: true; admin alone is insufficient.",
	}
	for _, op := range Operations() {
		opts := []mcp.ToolOption{mcp.WithDescription(descriptions[op.ToolName]), mcp.WithReadOnlyHintAnnotation(op.ReadOnly), mcp.WithDestructiveHintAnnotation(!op.ReadOnly), mcp.WithIdempotentHintAnnotation(op.ReadOnly)}
		for _, name := range requiredInputs(op.ToolName) {
			opts = append(opts, mcp.WithString(name, mcp.Required(), mcp.Pattern(`\S`)))
		}
		if op.Group == "aperture-pricing" {
			opts = append(opts, mcp.WithString("if_none_match", mcp.Description("Optional conditional pricing ETag")))
		}
		s.AddTool(mcp.NewTool(op.ToolName, opts...), func(ctx context.Context, req mcp.CallToolRequest) (result *mcp.CallToolResult, err error) {
			defer func() {
				if recover() != nil {
					result = mcp.NewToolResultError("Aperture operation failed; inspect configuration before retrying a write")
					err = nil
				}
			}()
			if check == nil {
				return mcp.NewToolResultError("Aperture access denied"), nil
			}
			if check(ctx, op.ToolName) != nil {
				return mcp.NewToolResultError("Aperture access denied"), nil
			}
			data, callErr := client.call(ctx, op, req.GetArguments())
			if callErr != nil {
				result = mcp.NewToolResultError(callErr.Error())
				var detail *toolError
				if errors.As(callErr, &detail) {
					result.StructuredContent = detail
				}
				return result, nil
			}
			text, _ := json.Marshal(data)
			result = mcp.NewToolResultText(string(text))
			result.StructuredContent = data
			return result, nil
		})
	}
}
