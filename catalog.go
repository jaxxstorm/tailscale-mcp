package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/jaxxstorm/tailscale-mcp/internal/curatedtools"
	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
	"github.com/jaxxstorm/tailscale-mcp/internal/toolmeta"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"
	tsapi "tailscale.com/client/tailscale/v2"
)

func newConfiguredMCPServer(tsClient *tsapi.Client, readClient readapi.Client, localCLI bool) (*server.MCPServer, *toolmeta.Catalog, error) {
	metadata := []toolmeta.Tool{{Name: "get_device_info", Group: "devices", ReadOnly: true}, {Name: "list_all_devices", Group: "devices", ReadOnly: true}}
	metadata = append(metadata, readapi.ToolMetadata()...)
	metadata = append(metadata, curatedtools.ToolMetadata(localCLI)...)
	catalog, err := toolmeta.New(metadata)
	if err != nil {
		return nil, nil, err
	}
	check := toolAccessChecker(catalog)
	s := server.NewMCPServer(mcpServerName, buildVersion,
		server.WithToolFilter(func(ctx context.Context, tools []mcp.Tool) []mcp.Tool {
			allowed := make([]mcp.Tool, 0, len(tools))
			for _, tool := range tools {
				if check(ctx, tool.Name) == nil {
					allowed = append(allowed, tool)
				}
			}
			return allowed
		}),
		server.WithToolHandlerMiddleware(recoverTool),
		server.WithResourceHandlerMiddleware(recoverResource),
	)
	registerCoreMCP(s, tsClient, check)
	readapi.RegisterTools(s, readClient, check)
	readapi.RegisterResources(s, readClient, checkResourceAccess)
	curatedtools.RegisterAll(s, curatedtools.Options{Client: readClient, Check: check, LocalCLI: localCLI})
	if err := catalog.Validate(s.ListTools()); err != nil {
		return nil, nil, err
	}
	return s, catalog, nil
}

// writeToolGroups builds the configured surface without contacting either API.
func writeToolGroups(w io.Writer, localCLI bool) error {
	_, catalog, err := newConfiguredMCPServer(nil, readapi.Client{}, localCLI)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(catalog.Tools())
}

func recoverTool(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (result *mcp.CallToolResult, err error) {
		defer func() {
			if recover() != nil {
				// Panic values can contain credentials; record only the operation.
				zap.L().Error("Tool handler panic recovered", zap.String("tool", req.Params.Name))
				result, err = mcp.NewToolResultError("internal server error"), nil
			}
		}()
		return next(ctx, req)
	}
}

func recoverResource(next server.ResourceHandlerFunc) server.ResourceHandlerFunc {
	return func(ctx context.Context, req mcp.ReadResourceRequest) (result []mcp.ResourceContents, err error) {
		defer func() {
			if recover() != nil {
				zap.L().Error("Resource handler panic recovered")
				result, err = nil, errors.New("internal server error")
			}
		}()
		return next(ctx, req)
	}
}
