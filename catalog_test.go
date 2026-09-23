package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jaxxstorm/tailscale-mcp/internal/curatedtools"
	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	tsapi "tailscale.com/client/tailscale/v2"
)

func dispatchGrantTest(t *testing.T, s *server.MCPServer, ctx context.Context, method string, params any) mcp.JSONRPCMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	return s.HandleMessage(ctx, raw)
}

func TestConfiguredCatalogParity(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprint(local), func(t *testing.T) {
			s, c, err := newConfiguredMCPServer(nil, readapi.Client{}, local)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Validate(s.ListTools()); err != nil {
				t.Fatal(err)
			}
			// Compare the complete schemas and annotations to unfiltered registration.
			baseline := server.NewMCPServer("baseline", "test")
			registerCoreMCP(baseline, nil, checkToolAccess)
			readapi.RegisterTools(baseline, readapi.Client{}, checkToolAccess)
			curatedtools.RegisterAll(baseline, curatedtools.Options{LocalCLI: local})
			if len(baseline.ListTools()) != len(c.Tools()) {
				t.Fatal("registration set changed")
			}
			for name, tool := range baseline.ListTools() {
				got := s.GetTool(name)
				if got == nil || !reflect.DeepEqual(got.Tool, tool.Tool) {
					t.Errorf("schema/annotations changed: %s", name)
				}
			}
			for _, name := range []string{"tailscale_get_acl", "tailscale_validate_acl", "tailscale_preview_acl", "tailscale_update_acl", "tailscale_set_devices_authorized", "tailscale_get_dns_configuration_curated", "tailscale_list_keys_curated", "tailscale_list_network_flow_logs"} {
				if s.GetTool(name) == nil {
					t.Errorf("existing wrapper/special handler missing: %s", name)
				}
			}
			for _, name := range []string{"tailscale_local_status", "tailscale_ping", "tailscale_netcheck", "tailscale_local_version"} {
				if c.Allows([]string{"*"}, name) != local || (s.GetTool(name) != nil) != local {
					t.Errorf("local opt-in mismatch: %s", name)
				}
			}
			for _, tool := range c.Tools() {
				if tool.ReadOnly != c.Allows([]string{"read:*"}, tool.Name) {
					t.Errorf("read annotation mismatch: %s", tool.Name)
				}
			}
			for _, name := range []string{"tailscale_validate_and_test_policy_file", "tailscale_preview_rule_matches", "tailscale_validate_acl"} {
				if !c.Allows([]string{"group:policy:read"}, name) {
					t.Errorf("read-like policy classification: %s", name)
				}
			}
			if c.Allows([]string{"read:*"}, "tailscale_get_aws_external_id") || !c.Allows([]string{"group:logging"}, "tailscale_get_aws_external_id") {
				t.Fatal("mutating get classification")
			}
		})
	}
}

func TestConfiguredProtocolGrantFiltering(t *testing.T) {
	cliDir := t.TempDir()
	marker := filepath.Join(cliDir, "called")
	if err := os.WriteFile(filepath.Join(cliDir, "tailscale"), []byte("#!/bin/sh\n: > \"$CLI_TEST_MARKER\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", cliDir)
	t.Setenv("CLI_TEST_MARKER", marker)
	var calls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer api.Close()
	baseURL, _ := url.Parse(api.URL)
	s, catalog, err := newConfiguredMCPServer(&tsapi.Client{BaseURL: baseURL, HTTP: api.Client()}, readapi.Client{BaseURL: api.URL, Tailnet: "test", HTTPClient: api.Client()}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, selectors := range [][]string{nil, {"tailscale_get_dns_configuration"}, {"*"}, {"read:*"}, {"group:dns"}, {"group:dns:read"}, {"read:*", "group:dns"}, {"group:unknown"}} {
		t.Run(fmt.Sprint(selectors), func(t *testing.T) {
			ctx := withCapabilities(context.Background(), &MCPCapability{Tools: selectors}, "caller")
			response := dispatchGrantTest(t, s, ctx, "initialize", map[string]any{"protocolVersion": mcp.LATEST_PROTOCOL_VERSION, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}})
			if _, ok := response.(mcp.JSONRPCResponse); !ok {
				t.Fatalf("initialize: %#v", response)
			}
			response = dispatchGrantTest(t, s, ctx, "tools/list", map[string]any{})
			listed, ok := response.(mcp.JSONRPCResponse)
			if !ok {
				t.Fatalf("list: %#v", response)
			}
			result, ok := listed.Result.(mcp.ListToolsResult)
			if !ok {
				t.Fatalf("list result: %T", listed.Result)
			}
			visible := map[string]bool{}
			for _, tool := range result.Tools {
				visible[tool.Name] = true
			}
			for _, tool := range catalog.Tools() {
				allowed := catalog.Allows(selectors, tool.Name)
				if visible[tool.Name] != allowed {
					t.Errorf("discovery mismatch: %s", tool.Name)
				}
				if allowed {
					continue
				}
				before := calls.Load()
				response := dispatchGrantTest(t, s, ctx, "tools/call", map[string]any{"name": tool.Name, "arguments": map[string]any{"deviceId": "123", "device": "123", "target": "example", "confirm": "deleteDevice", "body": map[string]any{}}})
				if _, ok := response.(mcp.JSONRPCError); !ok {
					t.Errorf("hidden tool was dispatchable: %s: %#v", tool.Name, response)
				}
				if calls.Load() != before {
					t.Fatalf("denied call contacted API: %s", tool.Name)
				}
			}
			// Exercise a valid permitted call, not only discovery and denials.
			if catalog.Allows(selectors, "tailscale_get_dns_configuration") {
				before := calls.Load()
				response := dispatchGrantTest(t, s, ctx, "tools/call", map[string]any{"name": "tailscale_get_dns_configuration", "arguments": map[string]any{}})
				rpc, ok := response.(mcp.JSONRPCResponse)
				if !ok || rpc.Result.(*mcp.CallToolResult).IsError || calls.Load() != before+1 {
					t.Fatalf("allowed read failed: %#v", response)
				}
			}
			// Authorized mutation still requires confirmation and must not call the API without it.
			if catalog.Allows(selectors, "tailscale_set_dns_configuration") {
				before := calls.Load()
				response := dispatchGrantTest(t, s, ctx, "tools/call", map[string]any{"name": "tailscale_set_dns_configuration", "arguments": map[string]any{"body": map[string]any{}}})
				if !response.(mcp.JSONRPCResponse).Result.(*mcp.CallToolResult).IsError || calls.Load() != before {
					t.Fatal("confirmation bypassed")
				}
			}
			before := calls.Load()
			for _, uri := range []string{"tailscale://devices", "tailscale://policy", "tailscale://dns/configuration", "tailscale://devices/123/routes", "bootstrap://status"} {
				response := dispatchGrantTest(t, s, ctx, "resources/read", map[string]any{"uri": uri})
				if _, ok := response.(mcp.JSONRPCError); !ok {
					t.Errorf("resource denial is not error: %s: %#v", uri, response)
				}
			}
			if calls.Load() != before {
				t.Fatal("resource denial contacted API")
			}
		})
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("denied tool started the local CLI")
	}
}

func TestCoreInvalidDeviceAndDirectDenials(t *testing.T) {
	var calls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = w.Write([]byte(`{}`)) }))
	defer api.Close()
	baseURL, _ := url.Parse(api.URL)
	s, _, err := newConfiguredMCPServer(&tsapi.Client{BaseURL: baseURL, HTTP: api.Client()}, readapi.Client{BaseURL: api.URL, HTTPClient: api.Client()}, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withCapabilities(context.Background(), &MCPCapability{Tools: []string{"*"}}, "alice")
	for _, args := range []any{nil, "wrong", []any{}, map[string]any{}, map[string]any{"device": nil}, map[string]any{"device": 42}, map[string]any{"device": map[string]any{}}, map[string]any{"device": ""}, map[string]any{"device": " \t\n"}} {
		response := dispatchGrantTest(t, s, ctx, "tools/call", map[string]any{"name": "get_device_info", "arguments": args})
		if rpc, ok := response.(mcp.JSONRPCResponse); ok {
			result := rpc.Result.(*mcp.CallToolResult)
			if !result.IsError || strings.Contains(result.Content[0].(mcp.TextContent).Text, "internal server error") {
				t.Errorf("invalid argument was not validated: %#v: %#v", args, result)
			}
		} else if _, ok := response.(mcp.JSONRPCError); !ok {
			t.Fatalf("unexpected response: %#v", response)
		}
	}
	for _, name := range []string{"get_device_info", "list_all_devices", "tailscale_get_dns_configuration", "tailscale_get_dns_configuration_curated"} {
		result, err := s.GetTool(name).Handler(context.Background(), mcp.CallToolRequest{})
		if err == nil && (result == nil || !result.IsError) {
			t.Errorf("handler check bypassed: %s", name)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid or denied operation contacted API")
	}
}

func TestConfiguredInputSchemaValidation(t *testing.T) {
	var calls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer api.Close()
	s, _, err := newConfiguredMCPServer(nil, readapi.Client{BaseURL: api.URL, HTTPClient: api.Client()}, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withCapabilities(context.Background(), &MCPCapability{Tools: []string{"*"}}, "alice")
	for _, tt := range []struct {
		tool, confirm, field string
		valid, invalid       any
	}{
		{"tailscale_device_update_key", "updateDeviceKey", "keyExpiryDisabled", false, "false"},
		{"tailscale_device_set_routes", "setDeviceRoutes", "routes", []string{"10.0.0.0/24"}, "10.0.0.0/24"},
		{"tailscale_device_set_tags", "setDeviceTags", "tags", []string{"tag:test"}, []any{42}},
	} {
		t.Run(tt.tool, func(t *testing.T) {
			for _, variant := range []string{"missing", "wrong type", "valid"} {
				t.Run(variant, func(t *testing.T) {
					args := map[string]any{"deviceId": "123", "confirm": tt.confirm}
					if variant == "valid" {
						args[tt.field] = tt.valid
					} else if variant == "wrong type" {
						args[tt.field] = tt.invalid
					}
					before := calls.Load()
					response := dispatchGrantTest(t, s, ctx, "tools/call", map[string]any{"name": tt.tool, "arguments": args})
					rpc, ok := response.(mcp.JSONRPCResponse)
					if !ok {
						t.Fatalf("unexpected response: %#v", response)
					}
					result := rpc.Result.(*mcp.CallToolResult)
					if variant == "valid" {
						if result.IsError || calls.Load() != before+1 {
							t.Fatalf("valid input failed: %#v", result)
						}
					} else if !result.IsError || calls.Load() != before || !strings.Contains(result.Content[0].(mcp.TextContent).Text, "input schema validation failed") {
						t.Fatalf("invalid input was not rejected before API dispatch: %#v", result)
					}
				})
			}
		})
	}
}

type grantTestSession struct{ notifications chan mcp.JSONRPCNotification }

func (*grantTestSession) Initialize()       {}
func (*grantTestSession) Initialized() bool { return true }
func (s *grantTestSession) NotificationChannel() chan<- mcp.JSONRPCNotification {
	return s.notifications
}
func (*grantTestSession) SessionID() string { return "reused-session-id" }

func TestRequestGrantsDoNotStickToSession(t *testing.T) {
	s, _, err := newConfiguredMCPServer(nil, readapi.Client{}, false)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	tool := s.GetTool("list_all_devices").Tool
	s.AddTool(tool, func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		calls.Add(1)
		return mcp.NewToolResultText("ok"), nil
	})
	session := &grantTestSession{notifications: make(chan mcp.JSONRPCNotification, 10)}
	if err := s.RegisterSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	defer s.UnregisterSession(context.Background(), session.SessionID())
	base := s.WithContext(context.Background(), session)
	for _, granted := range []bool{true, false, true, false} {
		caps := &MCPCapability{}
		if granted {
			caps.Tools = []string{"list_all_devices"}
		}
		ctx := withCapabilities(base, caps, fmt.Sprint(granted))
		response := dispatchGrantTest(t, s, ctx, "tools/list", map[string]any{})
		tools := response.(mcp.JSONRPCResponse).Result.(mcp.ListToolsResult).Tools
		if (len(tools) == 1) != granted || len(tools) > 1 {
			t.Fatalf("session discovery leaked grants: %v", tools)
		}
		before := calls.Load()
		response = dispatchGrantTest(t, s, ctx, "tools/call", map[string]any{"name": "list_all_devices"})
		_, denied := response.(mcp.JSONRPCError)
		if denied == granted || (calls.Load() == before+1) != granted {
			t.Fatal("session call leaked grants")
		}
	}
}

func TestSanitizedRecoveryAndNextRequest(t *testing.T) {
	s, _, err := newConfiguredMCPServer(nil, readapi.Client{}, false)
	if err != nil {
		t.Fatal(err)
	}
	// Replace registered handlers to exercise the production middleware, retaining
	// the catalog identity so call-time filtering still applies.
	tool := s.GetTool("list_all_devices").Tool
	s.AddTool(tool, func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		panic("credential-secret stack trace")
	})
	s.AddResource(mcp.NewResource("test://panic", "panic"), func(context.Context, mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		panic("credential-secret stack trace")
	})
	ctx := withCapabilities(context.Background(), &MCPCapability{Tools: []string{"*"}, Resources: []string{"*"}}, "alice")
	for _, request := range []struct {
		method string
		params any
	}{
		{"tools/call", map[string]any{"name": "list_all_devices"}},
		{"resources/read", map[string]any{"uri": "test://panic"}},
	} {
		response := dispatchGrantTest(t, s, ctx, request.method, request.params)
		data, _ := json.Marshal(response)
		if !strings.Contains(string(data), "internal server error") || strings.Contains(string(data), "credential-secret") || strings.Contains(string(data), "stack trace") {
			t.Fatalf("unsanitized recovery: %s", data)
		}
		next := dispatchGrantTest(t, s, ctx, "resources/read", map[string]any{"uri": "bootstrap://status"})
		if _, ok := next.(mcp.JSONRPCResponse); !ok {
			t.Fatalf("server failed after recovery: %#v", next)
		}
	}
}

func TestIndependentConfiguredServers(t *testing.T) {
	for i := range 16 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			local := i%2 == 0
			s, catalog, err := newConfiguredMCPServer(nil, readapi.Client{}, local)
			if err != nil {
				t.Fatal(err)
			}
			for range 10 {
				if catalog.Allows([]string{"group:local"}, "tailscale_ping") != local {
					t.Fatal("independent catalog changed")
				}
				if err := catalog.Validate(s.ListTools()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestOfflineToolGroupsDeterministic(t *testing.T) {
	for _, local := range []bool{false, true} {
		var first, second bytes.Buffer
		if err := writeToolGroups(&first, local); err != nil {
			t.Fatal(err)
		}
		if err := writeToolGroups(&second, local); err != nil {
			t.Fatal(err)
		}
		if first.String() != second.String() {
			t.Fatal("nondeterministic group listing")
		}
		if strings.Contains(first.String(), "tailscale_ping") != local {
			t.Fatal("group listing ignored local opt-in")
		}
	}
}
