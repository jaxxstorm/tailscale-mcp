package readapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestWithAccessDoesNotCallAPIWhenUnauthorized(t *testing.T) {
	called := false
	denied := errors.New("denied")
	_, err := withAccess(context.Background(), "tool:test", func(context.Context, string) error {
		return denied
	}, func() (string, error) {
		called = true
		return "", nil
	})
	if !errors.Is(err, denied) {
		t.Fatalf("expected denied error, got %v", err)
	}
	if called {
		t.Fatal("API helper was called after authorization failed")
	}
}

func TestValidateConfirmation(t *testing.T) {
	endpoint := Endpoint{OperationID: "deleteDevice", Confirm: "deleteDevice"}
	if err := validateConfirmation(endpoint, map[string]any{"confirm": "deleteDevice"}); err != nil {
		t.Fatalf("expected confirmation to pass: %v", err)
	}
	if err := validateConfirmation(endpoint, map[string]any{"confirm": "wrong"}); err == nil {
		t.Fatal("expected confirmation failure")
	}
}

func TestEndpointToolHints(t *testing.T) {
	tests := []struct {
		name string
		ep   Endpoint
		want ToolHints
	}{
		{name: "get", ep: Endpoint{Method: "GET"}, want: ToolHints{ReadOnly: true, Destructive: false, Idempotent: true}},
		{name: "read-like post", ep: Endpoint{Method: "POST", ReadLike: true}, want: ToolHints{ReadOnly: true, Destructive: false, Idempotent: true}},
		{name: "put", ep: Endpoint{Method: "PUT"}, want: ToolHints{ReadOnly: false, Destructive: false, Idempotent: true}},
		{name: "delete", ep: Endpoint{Method: "DELETE"}, want: ToolHints{ReadOnly: false, Destructive: true, Idempotent: true}},
		{name: "post", ep: Endpoint{Method: "POST"}, want: ToolHints{ReadOnly: false, Destructive: false, Idempotent: false}},
		{name: "patch", ep: Endpoint{Method: "PATCH"}, want: ToolHints{ReadOnly: false, Destructive: false, Idempotent: false}},
		{name: "destructive override", ep: Endpoint{Method: "POST", Destructive: true}, want: ToolHints{ReadOnly: false, Destructive: true, Idempotent: false}},
		{name: "idempotent override", ep: Endpoint{Method: "POST", Idempotent: Bool(true)}, want: ToolHints{ReadOnly: false, Destructive: false, Idempotent: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ep.ToolHints(); got != tt.want {
				t.Fatalf("ToolHints() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestRegisterToolsAppliesToolHints(t *testing.T) {
	mcpServer := server.NewMCPServer("test", "0.0.1")
	RegisterTools(mcpServer, Client{}, func(context.Context, string) error { return nil })

	tests := []struct {
		tool string
		want ToolHints
	}{
		{tool: "tailscale_get_dns_configuration", want: ToolHints{ReadOnly: true, Destructive: false, Idempotent: true}},
		{tool: "tailscale_validate_and_test_policy_file", want: ToolHints{ReadOnly: true, Destructive: false, Idempotent: true}},
		{tool: "tailscale_set_dns_configuration", want: ToolHints{ReadOnly: false, Destructive: false, Idempotent: true}},
		{tool: "tailscale_delete_device", want: ToolHints{ReadOnly: false, Destructive: true, Idempotent: true}},
		{tool: "tailscale_rotate_webhook_secret", want: ToolHints{ReadOnly: false, Destructive: true, Idempotent: false}},
		{tool: "tailscale_create_webhook", want: ToolHints{ReadOnly: false, Destructive: false, Idempotent: false}},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			tool := mcpServer.GetTool(tt.tool)
			if tool == nil {
				t.Fatalf("tool %q not registered", tt.tool)
			}
			assertToolAnnotations(t, tt.tool, tool.Tool.Annotations.ReadOnlyHint, tool.Tool.Annotations.DestructiveHint, tool.Tool.Annotations.IdempotentHint, tt.want)
		})
	}
}

func assertToolAnnotations(t *testing.T, name string, readOnly, destructive, idempotent *bool, want ToolHints) {
	t.Helper()
	if readOnly == nil || *readOnly != want.ReadOnly {
		t.Fatalf("%s readOnlyHint = %v, want %v", name, boolValue(readOnly), want.ReadOnly)
	}
	if destructive == nil || *destructive != want.Destructive {
		t.Fatalf("%s destructiveHint = %v, want %v", name, boolValue(destructive), want.Destructive)
	}
	if idempotent == nil || *idempotent != want.Idempotent {
		t.Fatalf("%s idempotentHint = %v, want %v", name, boolValue(idempotent), want.Idempotent)
	}
}

func boolValue(value *bool) any {
	if value == nil {
		return nil
	}
	return *value
}

func TestArgumentsFromURI(t *testing.T) {
	args, err := argumentsFromURI("tailscale://device/{deviceId}/routes", "tailscale://device/node-1/routes")
	if err != nil {
		t.Fatal(err)
	}
	if args["deviceId"] != "node-1" {
		t.Fatalf("unexpected deviceId %#v", args["deviceId"])
	}
	for _, uri := range []string{"tailscale://device//routes", "tailscale://device/node-1/routes/", "tailscale://device/node-1/attributes", "tailscale://device/node-1/extra/routes"} {
		if _, err := argumentsFromURI("tailscale://device/{deviceId}/routes", uri); err == nil {
			t.Errorf("accepted invalid URI %q", uri)
		}
	}
}

func TestResourceTemplateBindsAPIArgumentsToURI(t *testing.T) {
	for _, resource := range ResourceTemplates() {
		t.Run(resource.OperationID, func(t *testing.T) {
			var calls atomic.Int64
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				want, _, err := Expand(resource.Endpoint, "test", map[string]any{"deviceId": "allowed"})
				if err != nil || r.URL.Path != want || r.URL.RawQuery != "" {
					t.Errorf("API target = %s, want %s (expansion error: %v)", r.URL, want, err)
				}
				_, _ = w.Write([]byte(`{}`))
			}))
			defer api.Close()
			// The SDK replaces wire arguments; inject a conflict at the handler boundary.
			s := server.NewMCPServer("test", "test", server.WithResourceHandlerMiddleware(func(next server.ResourceHandlerFunc) server.ResourceHandlerFunc {
				return func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
					req.Params.Arguments = map[string]any{"deviceId": "forbidden"}
					return next(ctx, req)
				}
			}))
			allowedURI := strings.ReplaceAll(resource.URI, "{deviceId}", "allowed")
			RegisterResources(s, Client{BaseURL: api.URL, HTTPClient: api.Client()}, func(_ context.Context, uri string) error {
				if uri != allowedURI {
					return errors.New("denied")
				}
				return nil
			})
			for _, allowed := range []bool{true, false} {
				uri := allowedURI
				if !allowed {
					uri = strings.ReplaceAll(resource.URI, "{deviceId}", "forbidden")
				}
				raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": map[string]any{"uri": uri}})
				if err != nil {
					t.Fatal(err)
				}
				response := s.HandleMessage(context.Background(), raw)
				if allowed {
					rpc, ok := response.(mcp.JSONRPCResponse)
					if !ok || rpc.Result.(mcp.ReadResourceResult).Contents[0].(mcp.TextResourceContents).URI != allowedURI {
						t.Fatalf("allowed read: %#v", response)
					}
				} else if _, ok := response.(mcp.JSONRPCError); !ok {
					t.Fatalf("denied read: %#v", response)
				}
				if calls.Load() != 1 {
					t.Fatalf("API calls = %d, want 1", calls.Load())
				}
			}
		})
	}
}
