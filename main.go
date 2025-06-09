// main.go

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"net"

	"github.com/alecthomas/kong"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/tailscale/hujson"
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
	Stdio    bool   `help:"Use stdio mode instead of HTTP" default:"false"`
}

var buildVersion = "0.0.2"

// MCPCapability represents MCP-specific capabilities from Tailscale grants
type MCPCapability struct {
	Tools     []string `json:"tools"`
	Resources []string `json:"resources"`
}

// getTailscaleCapabilities extracts MCP capabilities from the request context
func getTailscaleCapabilities(ctx context.Context) (*MCPCapability, string, error) {
	// The CapMap is actually tailcfg.PeerCapMap, but we can treat it as map[string]interface{}
	capMapRaw := ctx.Value("ts-grants")
	if capMapRaw == nil {
		return nil, "", fmt.Errorf("no tailscale grants found in context")
	}
	
	// Convert to map[string]interface{} - this should work regardless of the underlying type
	capBytes, err := json.Marshal(capMapRaw)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal capMap: %v", err)
	}
	
	var capMap map[string]interface{}
	if err := json.Unmarshal(capBytes, &capMap); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal capMap: %v", err)
	}

	userLogin, ok := ctx.Value("ts-user").(string)
	if !ok {
		userLogin = "unknown"
	}

	log.Printf("[GRANTS] Checking capabilities for user: %s", userLogin)
	log.Printf("[GRANTS] Available grant keys: %v", func() []string {
		var keys []string
		for k := range capMap {
			keys = append(keys, k)
		}
		return keys
	}())

	// Look for jaxxstorm.com/cap/mcp capabilities
	if rawCaps, ok := capMap["jaxxstorm.com/cap/mcp"]; ok {
		log.Printf("[GRANTS] Found jaxxstorm.com/cap/mcp capabilities: %+v", rawCaps)
		
		// Marshal and unmarshal to handle the interface{} properly
		capBytes, err := json.Marshal(rawCaps)
		if err != nil {
			log.Printf("[GRANTS] Failed to marshal capability: %v", err)
			return nil, userLogin, fmt.Errorf("failed to marshal capability: %v", err)
		}

		log.Printf("[GRANTS] Capability JSON: %s", string(capBytes))

		// Parse as array of MCPCapability (similar to TACLAppCapabilities pattern)
		var mcpCaps []MCPCapability
		if err := json.Unmarshal(capBytes, &mcpCaps); err != nil {
			log.Printf("[GRANTS] Failed to parse as array, trying single object: %v", err)
			
			// Try parsing as single object
			var mcpCap MCPCapability
			if err := json.Unmarshal(capBytes, &mcpCap); err != nil {
				log.Printf("[GRANTS] Failed to parse MCP capability: %v", err)
				return nil, userLogin, fmt.Errorf("failed to parse MCP capability: %v", err)
			}
			
			log.Printf("[GRANTS] Parsed single capability: tools=%v, resources=%v", mcpCap.Tools, mcpCap.Resources)
			return &mcpCap, userLogin, nil
		}

		// If we successfully parsed as array, take the first one
		if len(mcpCaps) > 0 {
			log.Printf("[GRANTS] Parsed array capability: tools=%v, resources=%v", mcpCaps[0].Tools, mcpCaps[0].Resources)
			return &mcpCaps[0], userLogin, nil
		}
	}

	log.Printf("[GRANTS] No jaxxstorm.com/cap/mcp capabilities found")
	return nil, userLogin, nil
}


// checkToolAccess validates if the user has access to a specific tool
func checkToolAccess(ctx context.Context, toolName string) error {
	caps, user, err := getTailscaleCapabilities(ctx)
	if err != nil {
		log.Printf("[ACCESS DENIED] Failed to get capabilities: %v", err)
		return fmt.Errorf("access denied: unable to verify permissions")
	}

	if caps == nil {
		log.Printf("[ACCESS DENIED] No MCP capabilities found for user %s", user)
		return fmt.Errorf("access denied: no MCP permissions configured")
	}

	// Check if user has access to this specific tool
	for _, allowedTool := range caps.Tools {
		if allowedTool == "*" || allowedTool == toolName {
			log.Printf("[ACCESS GRANTED] User %s can access tool: %s", user, toolName)
			return nil
		}
	}

	log.Printf("[ACCESS DENIED] User %s cannot access tool: %s (allowed: %v)", user, toolName, caps.Tools)
	return fmt.Errorf("access denied: insufficient permissions for tool '%s'", toolName)
}

// checkResourceAccess validates if the user has access to a specific resource
func checkResourceAccess(ctx context.Context, resourceURI string) error {
	caps, user, err := getTailscaleCapabilities(ctx)
	if err != nil {
		log.Printf("[ACCESS DENIED] Failed to get capabilities: %v", err)
		return fmt.Errorf("access denied: unable to verify permissions")
	}

	if caps == nil {
		log.Printf("[ACCESS DENIED] No MCP capabilities found for user %s", user)
		return fmt.Errorf("access denied: no MCP permissions configured")
	}

	// Check if user has access to this specific resource
	for _, allowedResource := range caps.Resources {
		if allowedResource == "*" || allowedResource == resourceURI || strings.HasPrefix(resourceURI, allowedResource) {
			log.Printf("[ACCESS GRANTED] User %s can access resource: %s", user, resourceURI)
			return nil
		}
	}

	log.Printf("[ACCESS DENIED] User %s cannot access resource: %s (allowed: %v)", user, resourceURI, caps.Resources)
	return fmt.Errorf("access denied: insufficient permissions for resource '%s'", resourceURI)
}

// loggingMiddleware logs all incoming requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[REQUEST] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		// Log headers for debugging
		log.Printf("[HEADERS] User-Agent: %s", r.Header.Get("User-Agent"))
		if sessionID := r.Header.Get("Mcp-Session-Id"); sessionID != "" {
			log.Printf("[SESSION] MCP Session ID: %s", sessionID)
		}
		if user := r.Header.Get("X-Tailscale-User"); user != "" {
			log.Printf("[TAILSCALE] User: %s", user)
		}
		if node := r.Header.Get("X-Tailscale-Node"); node != "" {
			log.Printf("[TAILSCALE] Node: %s", node)
		}

		next.ServeHTTP(w, r)
	})
}

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

	mcpServer := server.NewMCPServer("ts-mcp", buildVersion)

	// Add empty prompts support to prevent errors
	log.Println("Adding prompts capability (empty)")
	mcpServer.AddPrompt(mcp.NewPrompt("empty"),
		func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{
				Messages: []mcp.PromptMessage{},
			}, nil
		})

	// Resource: status
	mcpServer.AddResource(mcp.NewResource("bootstrap://status", "Health-check",
		mcp.WithMIMEType("text/plain")),
		func(ctx context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			log.Println("[RESOURCE] bootstrap://status requested")
			
			// Check access
			if err := checkResourceAccess(ctx, "bootstrap://status"); err != nil {
				return nil, err
			}
			
			return []mcp.ResourceContents{
				mcp.TextResourceContents{URI: "bootstrap://status", MIMEType: "text/plain", Text: "up"},
			}, nil
		})

	devicesResource := mcp.NewResource(
		"tailscale://devices",
		"List all devices in the tailnet",
		mcp.WithMIMEType("application/json"),
	)

	mcpServer.AddResource(devicesResource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		log.Println("[RESOURCE] tailscale://devices requested")
		
		// Check access
		if err := checkResourceAccess(ctx, "tailscale://devices"); err != nil {
			return nil, err
		}
		
		devices, err := tsAdminClient.Devices().ListWithAllFields(ctx)
		if err != nil {
			log.Printf("[ERROR] Failed to list devices: %v", err)
			return nil, err
		}

		data, err := json.MarshalIndent(devices, "", "  ")
		if err != nil {
			log.Printf("[ERROR] Failed to marshal devices: %v", err)
			return nil, err
		}

		log.Printf("[SUCCESS] Retrieved %d devices", len(devices))
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "tailscale://devices",
				MIMEType: "application/json",
				Text:     string(data),
			},
		}, nil
	})

	// Resource: policy_file
	policyResource := mcp.NewResource(
		"tailscale://policy",
		"Fetch the current Tailscale policy file (ACL)",
		mcp.WithMIMEType("application/json"),
	)

	mcpServer.AddResource(policyResource,
		func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			log.Println("[RESOURCE] tailscale://policy requested")
			
			// Check access
			if err := checkResourceAccess(ctx, "tailscale://policy"); err != nil {
				return nil, err
			}
			
			policy, err := tsAdminClient.PolicyFile().Raw(ctx)
			if err != nil {
				log.Printf("[ERROR] Failed to fetch policy file: %v", err)
				return nil, fmt.Errorf("failed to fetch policy file: %w", err)
			}

			parsed, err := hujson.Parse([]byte(policy.HuJSON))
			if err != nil {
				log.Printf("[ERROR] Failed to parse HuJSON policy file: %v", err)
				return nil, fmt.Errorf("failed to parse HuJSON policy file: %w", err)
			}
			parsed.Standardize()

			var standardizedPolicy interface{}
			if err := json.Unmarshal(parsed.Pack(), &standardizedPolicy); err != nil {
				log.Printf("[ERROR] Failed to unmarshal standardized policy JSON: %v", err)
				return nil, fmt.Errorf("failed to unmarshal standardized policy JSON: %w", err)
			}

			data, err := json.MarshalIndent(standardizedPolicy, "", "  ")
			if err != nil {
				log.Printf("[ERROR] Failed to marshal standardized policy JSON: %v", err)
				return nil, fmt.Errorf("failed to marshal standardized policy JSON: %w", err)
			}

			log.Println("[SUCCESS] Retrieved policy file")
			return []mcp.ResourceContents{
				mcp.TextResourceContents{
					URI:      "tailscale://policy",
					MIMEType: "application/json",
					Text:     string(data),
				},
			}, nil
		})

	// Resource: Tailnet Settings
	mcpServer.AddResource(mcp.NewResource("tailscale://tailnet-settings", "Tailnet Settings",
		mcp.WithMIMEType("application/json"),
	), func(ctx context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		log.Println("[RESOURCE] tailscale://tailnet-settings requested")
		
		// Check access
		if err := checkResourceAccess(ctx, "tailscale://tailnet-settings"); err != nil {
			return nil, err
		}
		
		settings, err := tsAdminClient.TailnetSettings().Get(ctx)
		if err != nil {
			log.Printf("[ERROR] Failed to fetch tailnet settings: %v", err)
			return nil, fmt.Errorf("failed to fetch tailnet settings: %w", err)
		}

		data, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			log.Printf("[ERROR] Failed to marshal tailnet settings: %v", err)
			return nil, fmt.Errorf("failed to marshal tailnet settings: %w", err)
		}

		log.Println("[SUCCESS] Retrieved tailnet settings")
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "tailscale://tailnet-settings",
				MIMEType: "application/json",
				Text:     string(data),
			},
		}, nil
	})

	// Resource: device
	deviceResource := mcp.NewResource(
		"tailscale://device",
		"Query device details by ID or hostname",
		mcp.WithMIMEType("application/json"),
	)
	mcpServer.AddResource(deviceResource,
		func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			deviceID, ok := req.Params.Arguments["device"].(string)
			if !ok || deviceID == "" {
				log.Println("[ERROR] Device parameter required for tailscale://device")
				return nil, fmt.Errorf("device parameter required")
			}

			log.Printf("[RESOURCE] tailscale://device requested for: %s", deviceID)
			
			// Check access
			if err := checkResourceAccess(ctx, "tailscale://device"); err != nil {
				return nil, err
			}
			
			device, err := findDevice(ctx, tsAdminClient, deviceID)
			if err != nil {
				log.Printf("[ERROR] Failed to find device %s: %v", deviceID, err)
				return nil, err
			}

			data, err := json.MarshalIndent(device, "", "  ")
			if err != nil {
				log.Printf("[ERROR] Failed to marshal device %s: %v", deviceID, err)
				return nil, err
			}

			log.Printf("[SUCCESS] Retrieved device: %s", deviceID)
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
		log.Printf("[TOOL] get_device_info called")
		
		// Check access
		if err := checkToolAccess(ctx, "get_device_info"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			log.Println("[TOOL ERROR] get_device_info: invalid arguments format")
			return mcp.NewToolResultError("invalid arguments format"), nil
		}
		deviceID := args["device"].(string)
		log.Printf("[TOOL] get_device_info called for device: %s", deviceID)

		device, err := findDevice(ctx, tsAdminClient, deviceID)
		if err != nil {
			log.Printf("[TOOL ERROR] get_device_info: %v", err)
			return mcp.NewToolResultErrorFromErr("Device lookup failed", err), nil
		}
		data, err := json.MarshalIndent(device, "", "  ")
		if err != nil {
			log.Printf("[TOOL ERROR] get_device_info: JSON marshal failed: %v", err)
			return mcp.NewToolResultErrorFromErr("JSON marshal failed", err), nil
		}
		log.Printf("[TOOL SUCCESS] get_device_info retrieved device: %s", deviceID)
		return mcp.NewToolResultText(string(data)), nil
	})

	// Tool: list_all_devices
	mcpServer.AddTool(mcp.NewTool("list_all_devices",
		mcp.WithDescription("List all devices in the tailnet"),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		log.Println("[TOOL] list_all_devices called")
		
		// Check access
		if err := checkToolAccess(ctx, "list_all_devices"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		
		devices, err := tsAdminClient.Devices().List(ctx)
		if err != nil {
			log.Printf("[TOOL ERROR] list_all_devices: %v", err)
			return mcp.NewToolResultErrorFromErr("Failed to list devices", err), nil
		}

		data, err := json.MarshalIndent(devices, "", "  ")
		if err != nil {
			log.Printf("[TOOL ERROR] list_all_devices: JSON marshal failed: %v", err)
			return mcp.NewToolResultErrorFromErr("JSON marshal failed", err), nil
		}

		log.Printf("[TOOL SUCCESS] list_all_devices retrieved %d devices", len(devices))
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
	log.Printf("Serving MCP via Tailscale at http://%s/mcp\n", tsLn.Addr())

	streamable := server.NewStreamableHTTPServer(
		mcpServer,
		server.WithEndpointPath("/mcp"),
	)

	allowOrigin := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && !strings.HasPrefix(origin, "http://"+r.Host) && !strings.HasPrefix(origin, "https://"+r.Host) {
				log.Printf("[SECURITY] Forbidden origin: %s", origin)
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	mux := http.NewServeMux()

	// Add logging middleware to the chain
	mux.Handle("/mcp", loggingMiddleware(allowOrigin(grantMiddleware(streamable, tsServer))))

	handlerWithMiddleware := mux

	go func() {
		localAddr := "127.0.0.1:8080"
		log.Printf("Serving MCP http locally at http://%s\n", localAddr)
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
func grantMiddleware(next http.Handler, tsServer *tsnet.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse IP from remote address
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Printf("[GRANTS ERROR] Failed to parse IP from RemoteAddr: %v", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Get the LocalClient from tsnet server
		tsLocalClient, err := tsServer.LocalClient()
		if err != nil {
			log.Printf("[GRANTS ERROR] Failed to get LocalClient: %v", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		who, err := tsLocalClient.WhoIs(r.Context(), ip)
		if err != nil {
			log.Printf("[GRANTS ERROR] WhoIs error for IP %s: %v", ip, err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		userLoginName := ""
		if who.UserProfile != nil {
			userLoginName = who.UserProfile.LoginName
		}

		log.Printf("[GRANTS] Authorized user: %s from IP: %s", userLoginName, ip)
		log.Printf("[GRANTS] CapMap: %+v", who.CapMap)
		log.Printf("[GRANTS] CapMap type: %T", who.CapMap)
		
		// Add both grants and user info to context using the correct types
		ctx := context.WithValue(r.Context(), "ts-grants", who.CapMap)
		ctx = context.WithValue(ctx, "ts-user", userLoginName)
		
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}