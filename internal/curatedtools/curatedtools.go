package curatedtools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const localCLITimeout = 30 * time.Second

type Options struct {
	Client   readapi.Client
	Check    readapi.AccessChecker
	LocalCLI bool
}

type toolDef struct {
	Name        string
	Description string
	Endpoint    readapi.Endpoint
	Options     []mcp.ToolOption
	ReadOnly    bool
	Destructive bool
	Idempotent  bool
	Confirm     string
	Handler     func(context.Context, map[string]any) (any, error)
}

func RegisterAll(s *server.MCPServer, opts Options) {
	for _, def := range curatedTools(opts) {
		registerTool(s, opts, def)
	}
	if opts.LocalCLI {
		for _, def := range localCLITools() {
			registerTool(s, opts, def)
		}
	}
}

func curatedTools(opts Options) []toolDef {
	tools := []toolDef{}
	tools = append(tools, statusTools(opts)...)
	tools = append(tools, aclTools(opts)...)
	tools = append(tools, deviceTools(opts)...)
	tools = append(tools, domainWrapperTools(opts)...)
	return tools
}

func registerTool(s *server.MCPServer, opts Options, def toolDef) {
	toolOptions := []mcp.ToolOption{
		mcp.WithDescription(def.Description),
		mcp.WithReadOnlyHintAnnotation(def.ReadOnly),
		mcp.WithDestructiveHintAnnotation(def.Destructive),
		mcp.WithIdempotentHintAnnotation(def.Idempotent),
		mcp.WithOpenWorldHintAnnotation(true),
	}
	toolOptions = append(toolOptions, def.Options...)
	if def.Confirm != "" {
		toolOptions = append(toolOptions, mcp.WithString("confirm", mcp.Required(), mcp.Description("Confirmation token; must equal "+def.Confirm)))
	}
	handler := def.Handler
	if handler == nil {
		handler = func(ctx context.Context, args map[string]any) (any, error) {
			return opts.Client.Do(ctx, def.Endpoint, args)
		}
	}
	s.AddTool(mcp.NewTool(def.Name, toolOptions...), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		if err := validateConfirm(def.Confirm, args); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if opts.Check != nil {
			if err := opts.Check(ctx, def.Name); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
		}
		result, err := handler(ctx, args)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		text, err := resultText(result)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(text), nil
	})
}

func validateConfirm(want string, args map[string]any) error {
	if want == "" {
		return nil
	}
	if fmt.Sprint(args["confirm"]) != want {
		return fmt.Errorf("confirmation required: set confirm to %s", want)
	}
	return nil
}

func resultText(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	case json.RawMessage:
		return prettyJSON(v), nil
	default:
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
}

func prettyJSON(data []byte) string {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return string(data)
	}
	formatted, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return string(data)
	}
	return string(formatted)
}

func stringArg(args map[string]any, name string) string {
	return strings.TrimSpace(fmt.Sprint(args[name]))
}

func boolArg(args map[string]any, name string) bool {
	value, _ := args[name].(bool)
	return value
}

func stringSliceArg(args map[string]any, name string) []string {
	raw, ok := args[name]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		items := make([]string, 0, len(v))
		for _, item := range v {
			items = append(items, fmt.Sprint(item))
		}
		return items
	default:
		return []string{fmt.Sprint(v)}
	}
}

func body(args map[string]any, value any) map[string]any {
	copy := map[string]any{}
	for key, val := range args {
		copy[key] = val
	}
	copy["body"] = value
	return copy
}

func statusTools(opts Options) []toolDef {
	return []toolDef{{
		Name:        "tailscale_status",
		Description: "Check Tailscale Admin API health by composing device and tailnet settings reads.",
		ReadOnly:    true,
		Idempotent:  true,
		Handler: func(ctx context.Context, _ map[string]any) (any, error) {
			devices, devicesErr := opts.Client.Do(ctx, readapi.Endpoint{Method: "GET", Path: "/tailnet/{tailnet}/devices", Parameters: []readapi.Parameter{readapi.Query("fields", "Fields", false)}}, map[string]any{"fields": "id"})
			settings, settingsErr := opts.Client.Do(ctx, readapi.Endpoint{Method: "GET", Path: "/tailnet/{tailnet}/settings"}, nil)
			if devicesErr != nil && settingsErr != nil {
				return nil, devicesErr
			}
			out := map[string]any{"connected": true, "tailnet": opts.Client.Tailnet}
			if devicesErr == nil {
				var decoded struct {
					Devices []any `json:"devices"`
				}
				_ = json.Unmarshal(devices, &decoded)
				out["deviceCount"] = len(decoded.Devices)
			} else {
				out["deviceCount"] = nil
				out["devicesError"] = devicesErr.Error()
			}
			if settingsErr == nil {
				out["settings"] = json.RawMessage(settings)
			} else {
				out["settings"] = nil
				out["settingsError"] = settingsErr.Error()
			}
			return out, nil
		},
	}}
}

func aclTools(opts Options) []toolDef {
	acl := readapi.Endpoint{Method: "GET", Path: "/tailnet/{tailnet}/acl"}
	return []toolDef{
		{Name: "tailscale_get_acl", Description: "Get the current HuJSON ACL policy and ETag for safe updates.", ReadOnly: true, Idempotent: true, Handler: func(ctx context.Context, args map[string]any) (any, error) {
			res, err := opts.Client.DoRaw(ctx, acl, args, nil, map[string]string{"Accept": "application/hujson"})
			if err != nil {
				return nil, err
			}
			return map[string]any{"policy": string(res.Body), "etag": res.Header.Get("ETag")}, nil
		}},
		{Name: "tailscale_validate_acl", Description: "Validate HuJSON ACL policy without applying it.", ReadOnly: true, Idempotent: true, Options: []mcp.ToolOption{mcp.WithString("policy", mcp.Required(), mcp.Description("Full HuJSON policy text"))}, Handler: func(ctx context.Context, args map[string]any) (any, error) {
			res, err := opts.Client.DoRaw(ctx, readapi.Endpoint{Method: "POST", Path: "/tailnet/{tailnet}/acl/validate"}, args, []byte(stringArg(args, "policy")), map[string]string{"Accept": "application/hujson", "Content-Type": "application/hujson"})
			if err != nil {
				return nil, err
			}
			text := strings.TrimSpace(string(res.Body))
			if text == "" || text == "{}" {
				return "ACL policy is valid.", nil
			}
			return text, nil
		}},
		{Name: "tailscale_preview_acl", Description: "Preview ACL rules for a user or IP:port without applying policy.", ReadOnly: true, Idempotent: true, Options: []mcp.ToolOption{mcp.WithString("policy", mcp.Required()), mcp.WithString("type", mcp.Required(), mcp.Description("user or ipport")), mcp.WithString("previewFor", mcp.Required())}, Handler: func(ctx context.Context, args map[string]any) (any, error) {
			res, err := opts.Client.DoRaw(ctx, readapi.Endpoint{Method: "POST", Path: "/tailnet/{tailnet}/acl/preview", Parameters: []readapi.Parameter{readapi.Query("type", "Preview type", true), readapi.Query("previewFor", "Preview subject", true)}}, args, []byte(stringArg(args, "policy")), map[string]string{"Accept": "application/json", "Content-Type": "application/hujson"})
			if err != nil {
				return nil, err
			}
			return json.RawMessage(res.Body), nil
		}},
		{Name: "tailscale_update_acl", Description: "Update HuJSON ACL policy using an ETag to avoid overwriting concurrent edits.", Idempotent: true, Confirm: "setPolicyFile", Options: []mcp.ToolOption{mcp.WithString("policy", mcp.Required()), mcp.WithString("etag", mcp.Required())}, Handler: func(ctx context.Context, args map[string]any) (any, error) {
			res, err := opts.Client.DoRaw(ctx, readapi.Endpoint{Method: "POST", Path: "/tailnet/{tailnet}/acl"}, args, []byte(stringArg(args, "policy")), map[string]string{"Accept": "application/hujson", "Content-Type": "application/hujson", "If-Match": stringArg(args, "etag")})
			if err != nil {
				return nil, err
			}
			return map[string]any{"policy": string(res.Body), "etag": res.Header.Get("ETag")}, nil
		}},
	}
}

func deviceTools(opts Options) []toolDef {
	_ = opts
	return []toolDef{
		{Name: "tailscale_list_devices", Description: "List devices with optional fields selection.", ReadOnly: true, Idempotent: true, Endpoint: readapi.Endpoint{Method: "GET", Path: "/tailnet/{tailnet}/devices", Parameters: []readapi.Parameter{readapi.Query("fields", "Fields to include", false)}}, Options: []mcp.ToolOption{mcp.WithString("fields", mcp.Description("Comma-separated fields or all"))}},
		{Name: "tailscale_get_device", Description: "Get detailed device information by ID.", ReadOnly: true, Idempotent: true, Endpoint: readapi.Endpoint{Method: "GET", Path: "/device/{deviceId}", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}}, Options: []mcp.ToolOption{mcp.WithString("deviceId", mcp.Required())}},
		{Name: "tailscale_device_routes", Description: "Get subnet routes advertised and enabled for a device.", ReadOnly: true, Idempotent: true, Endpoint: readapi.Endpoint{Method: "GET", Path: "/device/{deviceId}/routes", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}}, Options: []mcp.ToolOption{mcp.WithString("deviceId", mcp.Required())}},
		{Name: "tailscale_device_posture_attributes", Description: "Get posture attributes for a device.", ReadOnly: true, Idempotent: true, Endpoint: readapi.Endpoint{Method: "GET", Path: "/device/{deviceId}/attributes", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}}, Options: []mcp.ToolOption{mcp.WithString("deviceId", mcp.Required())}},
		deviceBoolTool(opts, "tailscale_device_authorize", "Authorize a device.", false, true),
		deviceBoolTool(opts, "tailscale_device_deauthorize", "Deauthorize a device.", true, false),
		{Name: "tailscale_device_delete", Description: "Delete a device from the tailnet.", Destructive: true, Idempotent: true, Confirm: "deleteDevice", Endpoint: readapi.Endpoint{Method: "DELETE", Path: "/device/{deviceId}", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}}, Options: []mcp.ToolOption{mcp.WithString("deviceId", mcp.Required())}},
		{Name: "tailscale_device_rename", Description: "Set a device name.", Idempotent: true, Confirm: "setDeviceName", Endpoint: readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/name", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}, Body: true}, Options: []mcp.ToolOption{mcp.WithString("deviceId", mcp.Required()), mcp.WithString("name", mcp.Required())}, Handler: namedBody(opts, readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/name", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}, Body: true}, "name")},
		{Name: "tailscale_device_expire_key", Description: "Expire a device key.", Destructive: true, Idempotent: true, Confirm: "expireDeviceKey", Endpoint: readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/expire", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}}, Options: []mcp.ToolOption{mcp.WithString("deviceId", mcp.Required())}},
		{Name: "tailscale_device_set_routes", Description: "Set enabled subnet routes for a device.", Idempotent: true, Confirm: "setDeviceRoutes", Endpoint: readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/routes", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}, Body: true}, Options: []mcp.ToolOption{mcp.WithString("deviceId", mcp.Required()), mcp.WithArray("routes", mcp.Required(), mcp.WithStringItems())}, Handler: routesBody(opts)},
		{Name: "tailscale_device_set_tags", Description: "Set ACL tags on a device.", Idempotent: true, Confirm: "setDeviceTags", Endpoint: readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/tags", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}, Body: true}, Options: []mcp.ToolOption{mcp.WithString("deviceId", mcp.Required()), mcp.WithArray("tags", mcp.Required(), mcp.WithStringItems())}, Handler: tagsBody(opts)},
		{Name: "tailscale_device_set_ip", Description: "Set the Tailscale IPv4 address for a device.", Idempotent: true, Confirm: "setDeviceIp", Endpoint: readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/ip", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}, Body: true}, Options: []mcp.ToolOption{mcp.WithString("deviceId", mcp.Required()), mcp.WithString("ipv4", mcp.Required())}, Handler: namedBody(opts, readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/ip", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}, Body: true}, "ipv4")},
		{Name: "tailscale_device_update_key", Description: "Update device key settings.", Idempotent: true, Confirm: "updateDeviceKey", Endpoint: readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/key", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}, Body: true}, Options: []mcp.ToolOption{mcp.WithString("deviceId", mcp.Required()), mcp.WithBoolean("keyExpiryDisabled", mcp.Required())}, Handler: func(ctx context.Context, args map[string]any) (any, error) {
			return opts.Client.Do(ctx, readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/key", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}, Body: true}, body(args, map[string]any{"keyExpiryDisabled": boolArg(args, "keyExpiryDisabled")}))
		}},
		{Name: "tailscale_device_set_posture_attribute", Description: "Set a custom posture attribute on a device.", Idempotent: true, Confirm: "setCustomDevicePostureAttributes", Endpoint: readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/attributes/{attributeKey}", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID"), readapi.RequiredPath("attributeKey", "Attribute key")}, Body: true}, Options: []mcp.ToolOption{mcp.WithString("deviceId", mcp.Required()), mcp.WithString("attributeKey", mcp.Required()), mcp.WithString("value", mcp.Required()), mcp.WithString("expiry")}, Handler: attributeSetBody(opts)},
		{Name: "tailscale_device_delete_posture_attribute", Description: "Delete a custom posture attribute from a device.", Destructive: true, Idempotent: true, Confirm: "deleteCustomDevicePostureAttributes", Endpoint: readapi.Endpoint{Method: "DELETE", Path: "/device/{deviceId}/attributes/{attributeKey}", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID"), readapi.RequiredPath("attributeKey", "Attribute key")}}, Options: []mcp.ToolOption{mcp.WithString("deviceId", mcp.Required()), mcp.WithString("attributeKey", mcp.Required())}},
		{Name: "tailscale_device_batch_update_posture_attributes", Description: "Batch update custom posture attributes.", Idempotent: true, Confirm: "batchUpdateCustomDevicePostureAttributes", Endpoint: readapi.Endpoint{Method: "PATCH", Path: "/tailnet/{tailnet}/device-attributes", Body: true}, Options: []mcp.ToolOption{mcp.WithObject("nodes", mcp.Required()), mcp.WithString("comment")}, Handler: batchAttributesBody(opts)},
		{Name: "tailscale_set_devices_authorized", Description: "Authorize or deauthorize multiple devices and report partial failures.", Destructive: true, Idempotent: true, Confirm: "tailscale_set_devices_authorized", Options: []mcp.ToolOption{mcp.WithArray("deviceIds", mcp.Required(), mcp.WithStringItems()), mcp.WithBoolean("authorized", mcp.Required())}, Handler: bulkAuthorizeHandler(opts)},
	}
}

func deviceBoolTool(opts Options, name, desc string, destructive bool, authorized bool) toolDef {
	endpoint := readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/authorized", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}, Body: true}
	return toolDef{Name: name, Description: desc, Destructive: destructive, Idempotent: true, Confirm: "authorizeDevice", Endpoint: endpoint, Options: []mcp.ToolOption{mcp.WithString("deviceId", mcp.Required())}, Handler: func(ctx context.Context, args map[string]any) (any, error) {
		return opts.Client.Do(ctx, endpoint, body(args, map[string]any{"authorized": authorized}))
	}}
}

func namedBody(opts Options, endpoint readapi.Endpoint, field string) func(context.Context, map[string]any) (any, error) {
	return func(ctx context.Context, args map[string]any) (any, error) {
		return opts.Client.Do(ctx, endpoint, body(args, map[string]any{field: args[field]}))
	}
}

func routesBody(opts Options) func(context.Context, map[string]any) (any, error) {
	endpoint := readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/routes", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}, Body: true}
	return func(ctx context.Context, args map[string]any) (any, error) {
		routes := stringSliceArg(args, "routes")
		for _, route := range routes {
			if !isCIDR(route) {
				return nil, fmt.Errorf("invalid route %q: must be CIDR", route)
			}
		}
		return opts.Client.Do(ctx, endpoint, body(args, map[string]any{"routes": routes}))
	}
}

func tagsBody(opts Options) func(context.Context, map[string]any) (any, error) {
	endpoint := readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/tags", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}, Body: true}
	return func(ctx context.Context, args map[string]any) (any, error) {
		tags := stringSliceArg(args, "tags")
		for _, tag := range tags {
			if !strings.HasPrefix(tag, "tag:") {
				return nil, fmt.Errorf("tag %q must start with tag:", tag)
			}
		}
		return opts.Client.Do(ctx, endpoint, body(args, map[string]any{"tags": tags}))
	}
}

func attributeSetBody(opts Options) func(context.Context, map[string]any) (any, error) {
	endpoint := readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/attributes/{attributeKey}", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID"), readapi.RequiredPath("attributeKey", "Attribute key")}, Body: true}
	return func(ctx context.Context, args map[string]any) (any, error) {
		if !strings.HasPrefix(stringArg(args, "attributeKey"), "custom:") {
			return nil, errors.New("attributeKey must start with custom:")
		}
		payload := map[string]any{"value": args["value"]}
		if expiry := stringArg(args, "expiry"); expiry != "" {
			payload["expiry"] = expiry
		}
		return opts.Client.Do(ctx, endpoint, body(args, payload))
	}
}

func batchAttributesBody(opts Options) func(context.Context, map[string]any) (any, error) {
	endpoint := readapi.Endpoint{Method: "PATCH", Path: "/tailnet/{tailnet}/device-attributes", Body: true}
	return func(ctx context.Context, args map[string]any) (any, error) {
		payload := map[string]any{"nodes": args["nodes"]}
		if comment := stringArg(args, "comment"); comment != "" {
			payload["comment"] = comment
		}
		return opts.Client.Do(ctx, endpoint, body(args, payload))
	}
}

func bulkAuthorizeHandler(opts Options) func(context.Context, map[string]any) (any, error) {
	endpoint := readapi.Endpoint{Method: "POST", Path: "/device/{deviceId}/authorized", Parameters: []readapi.Parameter{readapi.RequiredPath("deviceId", "Device ID")}, Body: true}
	return func(ctx context.Context, args map[string]any) (any, error) {
		ids := uniqueStrings(stringSliceArg(args, "deviceIds"))
		authorized := boolArg(args, "authorized")
		succeeded := []string{}
		failed := map[string]string{}
		for _, id := range ids {
			_, err := opts.Client.Do(ctx, endpoint, body(map[string]any{"deviceId": id}, map[string]any{"authorized": authorized}))
			if err != nil {
				failed[id] = err.Error()
				continue
			}
			succeeded = append(succeeded, id)
		}
		return map[string]any{"authorized": authorized, "succeeded": succeeded, "failed": failed}, nil
	}
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	unique := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		unique = append(unique, value)
	}
	return unique
}

func isCIDR(value string) bool {
	_, _, err := net.ParseCIDR(value)
	return err == nil
}

func localCLITools() []toolDef {
	return []toolDef{
		{Name: "tailscale_local_status", Description: "Get this machine's local Tailscale status via tailscale status --json.", ReadOnly: true, Idempotent: true, Handler: func(ctx context.Context, _ map[string]any) (any, error) {
			return runTailscaleCLI(ctx, []string{"status", "--json"}, true)
		}},
		{Name: "tailscale_ping", Description: "Probe latency to a tailnet node via tailscale ping.", ReadOnly: true, Idempotent: true, Options: []mcp.ToolOption{mcp.WithString("target", mcp.Required()), mcp.WithNumber("count")}, Handler: func(ctx context.Context, args map[string]any) (any, error) {
			target := stringArg(args, "target")
			if !validPingTarget(target) {
				return nil, fmt.Errorf("invalid ping target %q", target)
			}
			cliArgs := []string{"ping"}
			if count, ok := args["count"]; ok && fmt.Sprint(count) != "" {
				cliArgs = append(cliArgs, "-c", fmt.Sprint(count))
			}
			cliArgs = append(cliArgs, target)
			return runTailscaleCLI(ctx, cliArgs, false)
		}},
		{Name: "tailscale_netcheck", Description: "Run Tailscale network diagnostics via tailscale netcheck --format=json.", ReadOnly: true, Idempotent: true, Handler: func(ctx context.Context, _ map[string]any) (any, error) {
			return runTailscaleCLI(ctx, []string{"netcheck", "--format=json"}, true)
		}},
		{Name: "tailscale_local_version", Description: "Get the local tailscale CLI version.", ReadOnly: true, Idempotent: true, Handler: func(ctx context.Context, _ map[string]any) (any, error) {
			return runTailscaleCLI(ctx, []string{"version"}, false)
		}},
	}
}

func runTailscaleCLI(ctx context.Context, args []string, parseJSON bool) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, localCLITimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "tailscale", args...)
	data, err := cmd.CombinedOutput()
	if len(data) > 1<<20 {
		data = data[:1<<20]
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("tailscale %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(data)))
	}
	if parseJSON {
		var value any
		if err := json.Unmarshal(data, &value); err != nil {
			return nil, err
		}
		return value, nil
	}
	return strings.TrimSpace(string(data)), nil
}

var pingTargetRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$`)

func validPingTarget(target string) bool {
	if target == "" || len(target) > 253 || strings.HasPrefix(target, "-") {
		return false
	}
	if net.ParseIP(target) != nil {
		return true
	}
	if strings.Contains(target, "..") {
		return false
	}
	return pingTargetRE.MatchString(target)
}

func domainWrapperTools(opts Options) []toolDef {
	defs := []struct {
		name        string
		desc        string
		operationID string
	}{
		{"tailscale_get_dns_configuration_curated", "Get full DNS configuration.", "getDnsConfiguration"},
		{"tailscale_list_user_invites_curated", "List open user invites.", "listUserInvites"},
		{"tailscale_list_keys_curated", "List active keys visible to the credential.", "listTailnetKeys"},
		{"tailscale_list_configuration_audit_logs_curated", "List configuration audit logs.", "listConfigurationAuditLogs"},
		{"tailscale_list_services_curated", "List tailnet services.", "listServices"},
		{"tailscale_get_tailnet_settings_curated", "Get tailnet settings.", "getTailnetSettings"},
		{"tailscale_list_users_curated", "List users.", "listUsers"},
		{"tailscale_list_webhooks_curated", "List webhooks.", "listWebhooks"},
		{"tailscale_get_posture_integrations_curated", "List posture integrations.", "getPostureIntegrations"},
	}
	byOperation := map[string]readapi.Endpoint{}
	for _, endpoint := range readapi.ToolEndpoints() {
		byOperation[endpoint.OperationID] = endpoint
	}
	tools := []toolDef{}
	for _, def := range defs {
		endpoint, ok := byOperation[def.operationID]
		if !ok {
			continue
		}
		hints := endpoint.ToolHints()
		tools = append(tools, toolDef{Name: def.name, Description: def.desc, Endpoint: endpoint, Options: endpointOptions(endpoint), ReadOnly: hints.ReadOnly, Destructive: hints.Destructive, Idempotent: hints.Idempotent, Confirm: endpoint.Confirm})
	}
	tools = append(tools,
		toolDef{Name: "tailscale_set_dns_configuration_curated", Description: "Replace DNS configuration with a typed body.", Endpoint: readapi.Endpoint{Method: "POST", Path: "/tailnet/{tailnet}/dns/configuration", Body: true}, Idempotent: true, Confirm: "setDnsConfiguration", Options: []mcp.ToolOption{mcp.WithObject("body", mcp.Required(), mcp.Description("DNS configuration body"))}},
		toolDef{Name: "tailscale_create_user_invites_curated", Description: "Create user invites.", Endpoint: readapi.Endpoint{Method: "POST", Path: "/tailnet/{tailnet}/user-invites", Body: true}, Confirm: "createUserInvites", Options: []mcp.ToolOption{mcp.WithObject("body", mcp.Required())}},
		toolDef{Name: "tailscale_create_key_curated", Description: "Create an auth key or trust credential.", Endpoint: readapi.Endpoint{Method: "POST", Path: "/tailnet/{tailnet}/keys", Body: true}, Confirm: "createKey", Options: []mcp.ToolOption{mcp.WithObject("body", mcp.Required())}},
		toolDef{Name: "tailscale_create_webhook_curated", Description: "Create a webhook.", Endpoint: readapi.Endpoint{Method: "POST", Path: "/tailnet/{tailnet}/webhooks", Body: true}, Confirm: "createWebhook", Options: []mcp.ToolOption{mcp.WithObject("body", mcp.Required())}},
	)
	_ = opts
	return tools
}

func endpointOptions(endpoint readapi.Endpoint) []mcp.ToolOption {
	options := []mcp.ToolOption{}
	for _, param := range endpoint.Parameters {
		props := []mcp.PropertyOption{mcp.Description(param.Description)}
		if param.Required {
			props = append(props, mcp.Required())
		}
		options = append(options, mcp.WithString(param.Name, props...))
	}
	if endpoint.Body {
		options = append(options, mcp.WithObject("body", mcp.Description("JSON request body")))
	}
	return options
}
