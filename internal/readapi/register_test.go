package readapi

import (
	"context"
	"errors"
	"testing"

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
}
