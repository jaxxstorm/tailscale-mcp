// main.go

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/tailscale/hujson"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"
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
var logger *zap.Logger

// MCPCapability represents MCP-specific capabilities from Tailscale grants
type MCPCapability struct {
	Tools     []string `json:"tools"`
	Resources []string `json:"resources"`
}

// initLogger initializes the Zap logger based on environment and debug settings
func initLogger(debug bool) {
	var config zap.Config

	// Check if we're running in a TTY
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))

	if isTTY {
		// Pretty console output for TTY
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05")
	} else {
		// Structured JSON output for non-TTY (production/logging systems)
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	// Set log level based on debug flag
	if debug {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	var err error
	logger, err = config.Build()
	if err != nil {
		log.Fatal("Failed to initialize logger:", err)
	}

	// Replace standard logger with zap
	zap.ReplaceGlobals(logger)
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

	logger.Info("Checking capabilities",
		zap.String("user", userLogin),
		zap.Strings("grant_keys", func() []string {
			var keys []string
			for k := range capMap {
				keys = append(keys, k)
			}
			return keys
		}()),
	)

	// Look for jaxxstorm.com/cap/mcp capabilities
	if rawCaps, ok := capMap["jaxxstorm.com/cap/mcp"]; ok {
		logger.Debug("Found MCP capabilities", zap.Any("capabilities", rawCaps))

		// Marshal and unmarshal to handle the interface{} properly
		capBytes, err := json.Marshal(rawCaps)
		if err != nil {
			logger.Error("Failed to marshal capability", zap.Error(err))
			return nil, userLogin, fmt.Errorf("failed to marshal capability: %v", err)
		}

		logger.Debug("Capability JSON", zap.String("json", string(capBytes)))

		// Parse as array of MCPCapability (similar to TACLAppCapabilities pattern)
		var mcpCaps []MCPCapability
		if err := json.Unmarshal(capBytes, &mcpCaps); err != nil {
			logger.Debug("Failed to parse as array, trying single object", zap.Error(err))

			// Try parsing as single object
			var mcpCap MCPCapability
			if err := json.Unmarshal(capBytes, &mcpCap); err != nil {
				logger.Error("Failed to parse MCP capability", zap.Error(err))
				return nil, userLogin, fmt.Errorf("failed to parse MCP capability: %v", err)
			}

			logger.Info("Parsed single capability",
				zap.Strings("tools", mcpCap.Tools),
				zap.Strings("resources", mcpCap.Resources),
			)
			return &mcpCap, userLogin, nil
		}

		// If we successfully parsed as array, take the first one
		if len(mcpCaps) > 0 {
			logger.Info("Parsed array capability",
				zap.Strings("tools", mcpCaps[0].Tools),
				zap.Strings("resources", mcpCaps[0].Resources),
			)
			return &mcpCaps[0], userLogin, nil
		}
	}

	logger.Info("No MCP capabilities found")
	return nil, userLogin, nil
}

// checkToolAccess validates if the user has access to a specific tool
func checkToolAccess(ctx context.Context, toolName string) error {
	caps, user, err := getTailscaleCapabilities(ctx)
	if err != nil {
		logger.Error("Failed to get capabilities", zap.Error(err))
		return fmt.Errorf("access denied: unable to verify permissions")
	}

	if caps == nil {
		logger.Warn("No MCP capabilities found", zap.String("user", user))
		return fmt.Errorf("access denied: no MCP permissions configured")
	}

	// Check if user has access to this specific tool
	for _, allowedTool := range caps.Tools {
		if allowedTool == "*" || allowedTool == toolName {
			logger.Info("Tool access granted",
				zap.String("user", user),
				zap.String("tool", toolName),
			)
			return nil
		}
	}

	logger.Warn("Tool access denied",
		zap.String("user", user),
		zap.String("tool", toolName),
		zap.Strings("allowed_tools", caps.Tools),
	)
	return fmt.Errorf("access denied: insufficient permissions for tool '%s'", toolName)
}

// checkResourceAccess validates if the user has access to a specific resource
func checkResourceAccess(ctx context.Context, resourceURI string) error {
	caps, user, err := getTailscaleCapabilities(ctx)
	if err != nil {
		logger.Error("Failed to get capabilities", zap.Error(err))
		return fmt.Errorf("access denied: unable to verify permissions")
	}

	if caps == nil {
		logger.Warn("No MCP capabilities found", zap.String("user", user))
		return fmt.Errorf("access denied: no MCP permissions configured")
	}

	// Check if user has access to this specific resource
	for _, allowedResource := range caps.Resources {
		if allowedResource == "*" || allowedResource == resourceURI || strings.HasPrefix(resourceURI, allowedResource) {
			logger.Info("Resource access granted",
				zap.String("user", user),
				zap.String("resource", resourceURI),
			)
			return nil
		}
	}

	logger.Warn("Resource access denied",
		zap.String("user", user),
		zap.String("resource", resourceURI),
		zap.Strings("allowed_resources", caps.Resources),
	)
	return fmt.Errorf("access denied: insufficient permissions for resource '%s'", resourceURI)
}

// loggingMiddleware logs all incoming requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("HTTP Request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("user_agent", r.Header.Get("User-Agent")),
		)

		// Log additional headers for debugging
		if sessionID := r.Header.Get("Mcp-Session-Id"); sessionID != "" {
			logger.Debug("MCP Session", zap.String("session_id", sessionID))
		}
		if user := r.Header.Get("X-Tailscale-User"); user != "" {
			logger.Debug("Tailscale User", zap.String("user", user))
		}
		if node := r.Header.Get("X-Tailscale-Node"); node != "" {
			logger.Debug("Tailscale Node", zap.String("node", node))
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	var cli CLI
	kong.Parse(&cli)

	// Initialize logger early
	initLogger(cli.Debug)
	defer logger.Sync()

	if cli.Version {
		fmt.Println("ts-mcp", buildVersion)
		return
	}

	logger.Info("Starting ts-mcp",
		zap.String("version", buildVersion),
		zap.String("tailnet", cli.Tailnet),
		zap.String("hostname", cli.Hostname),
		zap.Int("port", cli.Port),
		zap.Bool("debug", cli.Debug),
		zap.Bool("stdio", cli.Stdio),
	)

	tsAdminClient := &tsapi.Client{
		Tailnet: cli.Tailnet,
		APIKey:  cli.APIKey,
	}

	mcpServer := server.NewMCPServer("ts-mcp", buildVersion)

	// Add empty prompts support to prevent errors
	logger.Debug("Adding prompts capability")
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
			logger.Debug("Resource requested", zap.String("resource", "bootstrap://status"))

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
		logger.Debug("Resource requested", zap.String("resource", "tailscale://devices"))

		// Check access
		if err := checkResourceAccess(ctx, "tailscale://devices"); err != nil {
			return nil, err
		}

		devices, err := tsAdminClient.Devices().ListWithAllFields(ctx)
		if err != nil {
			logger.Error("Failed to list devices", zap.Error(err))
			return nil, err
		}

		data, err := json.MarshalIndent(devices, "", "  ")
		if err != nil {
			logger.Error("Failed to marshal devices", zap.Error(err))
			return nil, err
		}

		logger.Info("Retrieved devices", zap.Int("count", len(devices)))
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
			logger.Debug("Resource requested", zap.String("resource", "tailscale://policy"))

			// Check access
			if err := checkResourceAccess(ctx, "tailscale://policy"); err != nil {
				return nil, err
			}

			policy, err := tsAdminClient.PolicyFile().Raw(ctx)
			if err != nil {
				logger.Error("Failed to fetch policy file", zap.Error(err))
				return nil, fmt.Errorf("failed to fetch policy file: %w", err)
			}

			parsed, err := hujson.Parse([]byte(policy.HuJSON))
			if err != nil {
				logger.Error("Failed to parse HuJSON policy file", zap.Error(err))
				return nil, fmt.Errorf("failed to parse HuJSON policy file: %w", err)
			}
			parsed.Standardize()

			var standardizedPolicy interface{}
			if err := json.Unmarshal(parsed.Pack(), &standardizedPolicy); err != nil {
				logger.Error("Failed to unmarshal standardized policy JSON", zap.Error(err))
				return nil, fmt.Errorf("failed to unmarshal standardized policy JSON: %w", err)
			}

			data, err := json.MarshalIndent(standardizedPolicy, "", "  ")
			if err != nil {
				logger.Error("Failed to marshal standardized policy JSON", zap.Error(err))
				return nil, fmt.Errorf("failed to marshal standardized policy JSON: %w", err)
			}

			logger.Info("Retrieved policy file")
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
		logger.Debug("Resource requested", zap.String("resource", "tailscale://tailnet-settings"))

		// Check access
		if err := checkResourceAccess(ctx, "tailscale://tailnet-settings"); err != nil {
			return nil, err
		}

		settings, err := tsAdminClient.TailnetSettings().Get(ctx)
		if err != nil {
			logger.Error("Failed to fetch tailnet settings", zap.Error(err))
			return nil, fmt.Errorf("failed to fetch tailnet settings: %w", err)
		}

		data, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			logger.Error("Failed to marshal tailnet settings", zap.Error(err))
			return nil, fmt.Errorf("failed to marshal tailnet settings: %w", err)
		}

		logger.Info("Retrieved tailnet settings")
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
				logger.Error("Device parameter required for tailscale://device")
				return nil, fmt.Errorf("device parameter required")
			}

			logger.Debug("Resource requested",
				zap.String("resource", "tailscale://device"),
				zap.String("device_id", deviceID),
			)

			// Check access
			if err := checkResourceAccess(ctx, "tailscale://device"); err != nil {
				return nil, err
			}

			device, err := findDevice(ctx, tsAdminClient, deviceID)
			if err != nil {
				logger.Error("Failed to find device", zap.String("device_id", deviceID), zap.Error(err))
				return nil, err
			}

			data, err := json.MarshalIndent(device, "", "  ")
			if err != nil {
				logger.Error("Failed to marshal device", zap.String("device_id", deviceID), zap.Error(err))
				return nil, err
			}

			logger.Info("Retrieved device", zap.String("device_id", deviceID))
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
		logger.Debug("Tool called", zap.String("tool", "get_device_info"))

		// Check access
		if err := checkToolAccess(ctx, "get_device_info"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			logger.Error("Invalid arguments format for get_device_info")
			return mcp.NewToolResultError("invalid arguments format"), nil
		}
		deviceID := args["device"].(string)
		logger.Debug("Tool parameters", zap.String("device_id", deviceID))

		device, err := findDevice(ctx, tsAdminClient, deviceID)
		if err != nil {
			logger.Error("Device lookup failed", zap.String("device_id", deviceID), zap.Error(err))
			return mcp.NewToolResultErrorFromErr("Device lookup failed", err), nil
		}
		data, err := json.MarshalIndent(device, "", "  ")
		if err != nil {
			logger.Error("JSON marshal failed", zap.String("device_id", deviceID), zap.Error(err))
			return mcp.NewToolResultErrorFromErr("JSON marshal failed", err), nil
		}
		logger.Info("Tool executed successfully",
			zap.String("tool", "get_device_info"),
			zap.String("device_id", deviceID),
		)
		return mcp.NewToolResultText(string(data)), nil
	})

	// Tool: list_all_devices
	mcpServer.AddTool(mcp.NewTool("list_all_devices",
		mcp.WithDescription("List all devices in the tailnet"),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger.Debug("Tool called", zap.String("tool", "list_all_devices"))

		// Check access
		if err := checkToolAccess(ctx, "list_all_devices"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		devices, err := tsAdminClient.Devices().List(ctx)
		if err != nil {
			logger.Error("Failed to list devices", zap.Error(err))
			return mcp.NewToolResultErrorFromErr("Failed to list devices", err), nil
		}

		data, err := json.MarshalIndent(devices, "", "  ")
		if err != nil {
			logger.Error("JSON marshal failed", zap.Error(err))
			return mcp.NewToolResultErrorFromErr("JSON marshal failed", err), nil
		}

		logger.Info("Tool executed successfully",
			zap.String("tool", "list_all_devices"),
			zap.Int("device_count", len(devices)),
		)
		return mcp.NewToolResultText(string(data)), nil
	})

	// stdio mode
	if cli.Stdio {
		logger.Info("Starting MCP server in stdio mode")
		if err := server.ServeStdio(mcpServer); err != nil {
			logger.Fatal("Stdio server error", zap.Error(err))
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
		logger.Fatal("tsnet listen error", zap.Error(err))
	}
	logger.Info("Serving MCP via Tailscale", zap.String("address", tsLn.Addr().String()))

	streamable := server.NewStreamableHTTPServer(
		mcpServer,
		server.WithEndpointPath("/mcp"),
	)

	allowOrigin := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && !strings.HasPrefix(origin, "http://"+r.Host) && !strings.HasPrefix(origin, "https://"+r.Host) {
				logger.Warn("Forbidden origin", zap.String("origin", origin))
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
		logger.Info("Serving MCP locally", zap.String("address", localAddr))
		if err := http.ListenAndServe(localAddr, handlerWithMiddleware); err != nil {
			logger.Fatal("Local server error", zap.Error(err))
		}
	}()

	if err := http.Serve(tsLn, handlerWithMiddleware); err != nil {
		logger.Fatal("Tailscale server error", zap.Error(err))
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
			logger.Error("Failed to parse IP from RemoteAddr", zap.Error(err))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Get the LocalClient from tsnet server
		tsLocalClient, err := tsServer.LocalClient()
		if err != nil {
			logger.Error("Failed to get LocalClient", zap.Error(err))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		who, err := tsLocalClient.WhoIs(r.Context(), ip)
		if err != nil {
			logger.Error("WhoIs error", zap.String("ip", ip), zap.Error(err))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		userLoginName := ""
		if who.UserProfile != nil {
			userLoginName = who.UserProfile.LoginName
		}

		logger.Info("Authorized user",
			zap.String("user", userLoginName),
			zap.String("ip", ip),
		)
		logger.Debug("User capabilities",
			zap.String("user", userLoginName),
			zap.Any("cap_map", who.CapMap),
		)

		// Add both grants and user info to context using the correct types
		ctx := context.WithValue(r.Context(), "ts-grants", who.CapMap)
		ctx = context.WithValue(ctx, "ts-user", userLoginName)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
