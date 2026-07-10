package readapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type AccessChecker func(context.Context, string) error

func withAccess[T any](ctx context.Context, item string, check AccessChecker, call func() (T, error)) (T, error) {
	var zero T
	if err := check(ctx, item); err != nil {
		return zero, err
	}
	return call()
}

func RegisterTools(mcpServer *server.MCPServer, client Client, check AccessChecker) {
	for _, endpoint := range ToolEndpoints() {
		endpoint := endpoint
		options := []mcp.ToolOption{mcp.WithDescription(endpoint.Summary)}
		options = append(options, ToolHintOptions(endpoint)...)
		for _, param := range endpoint.Parameters {
			if param.Location == QueryParam || param.Location == PathParam {
				props := []mcp.PropertyOption{mcp.Description(param.Description)}
				if param.Required {
					props = append(props, mcp.Required())
				}
				options = append(options, mcp.WithString(param.Name, props...))
			}
		}
		if endpoint.Body {
			options = append(options, mcp.WithObject("body", mcp.Description("JSON request body")))
		}
		if endpoint.Confirm != "" {
			options = append(options, mcp.WithString("confirm", mcp.Required(), mcp.Description("Confirmation token; must equal "+endpoint.Confirm)))
		}

		mcpServer.AddTool(mcp.NewTool(endpoint.ToolName, options...), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			if err := validateConfirmation(endpoint, args); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			data, err := withAccess(ctx, endpoint.ToolName, check, func() (json.RawMessage, error) {
				return client.Do(ctx, endpoint, args)
			})
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return mcp.NewToolResultText(prettyJSON(data)), nil
		})
	}
}

func ToolHintOptions(endpoint Endpoint) []mcp.ToolOption {
	hints := endpoint.ToolHints()
	return []mcp.ToolOption{
		mcp.WithReadOnlyHintAnnotation(hints.ReadOnly),
		mcp.WithDestructiveHintAnnotation(hints.Destructive),
		mcp.WithIdempotentHintAnnotation(hints.Idempotent),
	}
}

func RegisterResources(mcpServer *server.MCPServer, client Client, check AccessChecker) {
	for _, resource := range Resources() {
		resource := resource
		mcpServer.AddResource(mcp.NewResource(resource.URI, resource.Name, mcp.WithMIMEType("application/json")), func(ctx context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			data, err := withAccess(ctx, resource.URI, check, func() (json.RawMessage, error) {
				return client.Do(ctx, resource.Endpoint, map[string]any{})
			})
			if err != nil {
				return nil, err
			}
			return []mcp.ResourceContents{mcp.TextResourceContents{URI: resource.URI, MIMEType: "application/json", Text: prettyJSON(data)}}, nil
		})
	}

	for _, resource := range ResourceTemplates() {
		resource := resource
		mcpServer.AddResourceTemplate(mcp.NewResourceTemplate(resource.URI, resource.Name, mcp.WithTemplateMIMEType("application/json")), func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			args := req.Params.Arguments
			if len(args) == 0 {
				var err error
				args, err = argumentsFromURI(resource.URI, req.Params.URI)
				if err != nil {
					return nil, err
				}
			}
			data, err := withAccess(ctx, req.Params.URI, check, func() (json.RawMessage, error) {
				return client.Do(ctx, resource.Endpoint, args)
			})
			if err != nil {
				return nil, err
			}
			return []mcp.ResourceContents{mcp.TextResourceContents{URI: req.Params.URI, MIMEType: "application/json", Text: prettyJSON(data)}}, nil
		})
	}
}

func validateConfirmation(endpoint Endpoint, args map[string]any) error {
	if endpoint.Confirm == "" {
		return nil
	}
	if fmt.Sprint(args["confirm"]) != endpoint.Confirm {
		return fmt.Errorf("confirmation required: set confirm to %s", endpoint.Confirm)
	}
	return nil
}

func argumentsFromURI(template, uri string) (map[string]any, error) {
	templateParts := strings.Split(strings.Trim(template, "/"), "/")
	uriParts := strings.Split(strings.Trim(uri, "/"), "/")
	if len(templateParts) != len(uriParts) {
		return nil, errors.New("resource URI does not match template")
	}
	args := map[string]any{}
	for i, part := range templateParts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			args[strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")] = uriParts[i]
			continue
		}
		if part != uriParts[i] {
			return nil, errors.New("resource URI does not match template")
		}
	}
	return args, nil
}

func prettyJSON(data []byte) string {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return string(data)
	}
	formatted, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(formatted)
}
