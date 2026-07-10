package curatedtools

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestRegisterAllRegistersCuratedToolsWithoutLocalCLIByDefault(t *testing.T) {
	srv := server.NewMCPServer("test", "0.0.1")
	RegisterAll(srv, Options{Client: readapi.Client{Tailnet: "example.com"}, Check: allow})

	for _, name := range []string{"tailscale_status", "tailscale_get_acl", "tailscale_device_authorize", "tailscale_get_dns_configuration_curated"} {
		if srv.GetTool(name) == nil {
			t.Fatalf("expected tool %q to be registered", name)
		}
	}
	if srv.GetTool("tailscale_local_status") != nil {
		t.Fatal("local CLI tool registered without opt-in")
	}
}

func TestRegisterAllRegistersLocalCLIWhenEnabled(t *testing.T) {
	srv := server.NewMCPServer("test", "0.0.1")
	RegisterAll(srv, Options{Client: readapi.Client{Tailnet: "example.com"}, Check: allow, LocalCLI: true})
	for _, name := range []string{"tailscale_local_status", "tailscale_ping", "tailscale_netcheck", "tailscale_local_version"} {
		tool := srv.GetTool(name)
		if tool == nil {
			t.Fatalf("expected tool %q to be registered", name)
		}
		if tool.Tool.Annotations.ReadOnlyHint == nil || !*tool.Tool.Annotations.ReadOnlyHint {
			t.Fatalf("%s missing readOnlyHint", name)
		}
	}
}

func TestCuratedToolChecksGrantBeforeCallingAPI(t *testing.T) {
	called := false
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer backend.Close()

	srv := server.NewMCPServer("test", "0.0.1")
	RegisterAll(srv, Options{Client: readapi.Client{Tailnet: "example.com", BaseURL: backend.URL}, Check: func(context.Context, string) error { return errors.New("denied") }})
	tool := srv.GetTool("tailscale_status")
	if tool == nil {
		t.Fatal("tailscale_status not registered")
	}
	result, err := tool.Handler(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{}}})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("expected tool error result, got %#v", result)
	}
	if called {
		t.Fatal("API called after grant denial")
	}
}

func TestACLGetReturnsPolicyAndETag(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tailnet/example.com/acl" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("ETag", `"abc"`)
		_, _ = w.Write([]byte("// policy\n{}"))
	}))
	defer backend.Close()

	srv := server.NewMCPServer("test", "0.0.1")
	RegisterAll(srv, Options{Client: readapi.Client{Tailnet: "example.com", BaseURL: backend.URL}, Check: allow})
	tool := srv.GetTool("tailscale_get_acl")
	result, err := tool.Handler(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{}}})
	if err != nil {
		t.Fatal(err)
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "// policy") || !strings.Contains(text, `abc`) {
		t.Fatalf("unexpected ACL response %s", text)
	}
}

func TestValidateConfirm(t *testing.T) {
	if err := validateConfirm("deleteDevice", map[string]any{"confirm": "deleteDevice"}); err != nil {
		t.Fatal(err)
	}
	if err := validateConfirm("deleteDevice", map[string]any{"confirm": "wrong"}); err == nil {
		t.Fatal("expected confirmation error")
	}
}

func TestInputValidationHelpers(t *testing.T) {
	if !validPingTarget("host-1.example") || validPingTarget("-bad") || validPingTarget("bad..host") {
		t.Fatal("unexpected ping target validation result")
	}
	if !isCIDR("10.0.0.0/24") || isCIDR("10.0.0.0") {
		t.Fatal("unexpected CIDR validation result")
	}
}

func allow(context.Context, string) error { return nil }
