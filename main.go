// main.go


package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/alecthomas/kong"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"tailscale.com/client/local"
	tsapi "tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
)

type CLI struct {
	Tailnet  string `env:"TAILSCALE_TAILNET" required:""`
	APIKey   string `env:"TAILSCALE_API_KEY" required:""`
	Hostname string `env:"TS_HOSTNAME" default:"ts-mcp"`
	Port     int    `env:"TS_PORT" default:"8080"`
	AuthKey  string `env:"TS_AUTH_KEY" default:""`
	Debug    bool   `short:"d"`
	Version  bool   `short:"v"`
	Stdio    bool   `help:"Use stdio mode instead of SSE" default:"false"`
}

var buildVersion = "0.0.1"

func main() {
	var cli CLI
	kctx := kong.Parse(&cli)

	if cli.Version {
		fmt.Println("ts-mcp", buildVersion)
		return
	}

	tsAdminClient := &tsapi.Client{
		Tailnet: cli.Tailnet,
		APIKey:  cli.APIKey,
	}

	tsLocalClient := &local.Client{}

	mcpServer := server.NewMCPServer("ts-mcp", buildVersion)

	// Resource: status
	mcpServer.AddResource(mcp.NewResource("bootstrap://status", "Health-check",
		mcp.WithMIMEType("text/plain")),
		func(_ context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{URI: "bootstrap://status", MIMEType: "text/plain", Text: "up"},
			}, nil
		})

	// Resource: device
	// NOTE: many clients don't support resources right now
	deviceResource := mcp.NewResource(
		"tailscale://device",
		"Query device details by ID or hostname",
		mcp.WithMIMEType("application/json"),
	)
	mcpServer.AddResource(deviceResource,
		func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			deviceID, ok := req.Params.Arguments["device"].(string)
			if !ok || deviceID == "" {
				return nil, fmt.Errorf("device parameter required")
			}

			device, err := findDevice(ctx, tsAdminClient, deviceID)
			if err != nil {
				return nil, err
			}

			data, err := json.MarshalIndent(device, "", "  ")
			if err != nil {
				return nil, err
			}

			return []mcp.ResourceContents{
				mcp.TextResourceContents{
					URI:      fmt.Sprintf("tailscale://device/%s", deviceID),
					MIMEType: "application/json",
					Text:     string(data),
				},
			}, nil
		})

	// Tool wrapper for resource
	mcpServer.AddTool(mcp.NewTool("get_device_info",
		mcp.WithDescription("Fetch device details by ID, IP, or hostname"),
		mcp.WithString("device", mcp.Required(), mcp.Description("Device ID, IP, or hostname")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		deviceID := req.Params.Arguments["device"].(string)
		device, err := findDevice(ctx, tsAdminClient, deviceID)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("Device lookup failed", err), nil
		}
		data, err := json.MarshalIndent(device, "", "  ")
		if err != nil {
			return mcp.NewToolResultErrorFromErr("JSON marshal failed", err), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	})

	// Tool: list_all_devices
	mcpServer.AddTool(mcp.NewTool("list_all_devices",
		mcp.WithDescription("List all devices in the tailnet"),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		devices, err := tsAdminClient.Devices().List(ctx)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("Failed to list devices", err), nil
		}

		data, err := json.MarshalIndent(devices, "", "  ")
		if err != nil {
			return mcp.NewToolResultErrorFromErr("JSON marshal failed", err), nil
		}

		return mcp.NewToolResultText(string(data)), nil
	})

	// stdio mode
	if cli.Stdio {
		log.Println("Starting MCP server in stdio mode...")
		if err := server.ServeStdio(mcpServer); err != nil {
			log.Fatal("Stdio server error:", err)
		}
		os.Exit(0)
	}

	tsServer := &tsnet.Server{
		Hostname: cli.Hostname,
		AuthKey:  cli.AuthKey,
	}
	defer tsServer.Close()

	tsLn, err := tsServer.Listen("tcp", fmt.Sprintf(":%d", cli.Port))
	if err != nil {
		log.Fatal("tsnet listen error:", err)
	}
	log.Printf("Serving MCP SSE via Tailscale at http://%s\n", tsLn.Addr())

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/ai-plugin.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "ai-plugin.json")
	})

	sseServer := server.NewSSEServer(mcpServer,
		server.WithStaticBasePath("/"),
		server.WithSSEEndpoint("/sse"),
		server.WithMessageEndpoint("/message"),
	)
	mux.Handle("/", sseServer)

	handlerWithMiddleware := grantMiddleware(mux, tsLocalClient)

	go func() {
		localAddr := "127.0.0.1:8080"
		log.Printf("Serving MCP SSE locally at http://%s\n", localAddr)
		if err := http.ListenAndServe(localAddr, handlerWithMiddleware); err != nil {
			kctx.FatalIfErrorf(err)
		}
	}()

	if err := http.Serve(tsLn, handlerWithMiddleware); err != nil {
		kctx.FatalIfErrorf(err)
	}


}

// findDevice finds a device by ID, hostname, or IP and fetches detailed information.
func findDevice(ctx context.Context, client *tsapi.Client, id string) (*tsapi.Device, error) {
	devices, err := client.Devices().List(ctx)
	if err != nil {
		return nil, err
	}

	for _, d := range devices {
		if d.ID == id || d.Hostname == id {
			return client.Devices().GetWithAllFields(ctx, d.ID)
		}
		for _, addr := range d.Addresses {
			if addr == id {
				return client.Devices().GetWithAllFields(ctx, d.ID)
			}
		}
	}

	return nil, fmt.Errorf("device not found: %s", id)
}

// OAuth Grants Middleware
func grantMiddleware(next http.Handler, tsLocalClient *local.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, err := tsLocalClient.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			log.Printf("WhoIs error: %v", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "ts-grants", who.CapMap)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
