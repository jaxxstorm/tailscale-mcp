package readapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestRefreshedSchemaServices(t *testing.T) {
	service := `{"name":"svc:checkout","displayName":"Checkout API","ports":["tcp:443"],"tags":["tag:prod"],"comment":"existing field","futureField":{"enabled":true}}`
	list := `{"services":[` + service + `]}`
	for _, tc := range []struct {
		name, item, method, path, response string
		args                               map[string]any
		resource                           bool
	}{
		{"list", "tailscale_list_services", "GET", "/tailnet/example.com/services", list, nil, false},
		{"get", "tailscale_get_service", "GET", "/tailnet/example.com/services/svc:checkout", service, map[string]any{"serviceName": "svc:checkout"}, false},
		{"update", "tailscale_update_service", "PUT", "/tailnet/example.com/services/svc:checkout", service, map[string]any{"serviceName": "svc:checkout", "confirm": "updateService", "body": json.RawMessage(service)}, false},
		{"resource", "tailscale://services", "GET", "/tailnet/example.com/services", list, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != tc.method || r.URL.Path != tc.path || r.URL.RawQuery != "" {
					t.Errorf("request = %s %s, want %s %s", r.Method, r.URL, tc.method, tc.path)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if tc.method == "PUT" {
					assertRefreshedJSON(t, string(body), service)
				} else if len(body) != 0 {
					t.Errorf("unexpected request body: %s", body)
				}
				_, _ = io.WriteString(w, tc.response)
			}))
			defer api.Close()
			s := server.NewMCPServer("test", "test")
			allowed, checks := true, 0
			check := func(_ context.Context, item string) error {
				checks++
				if item != tc.item {
					t.Errorf("grant = %q, want existing grant %q", item, tc.item)
				}
				if !allowed {
					return errors.New("denied")
				}
				return nil
			}
			client := Client{Tailnet: "example.com", BaseURL: api.URL, HTTPClient: api.Client()}
			RegisterTools(s, client, check)
			RegisterResources(s, client, check)
			text, failed := callRefreshedMCP(t, s, tc.item, tc.args, tc.resource)
			if failed {
				t.Fatalf("call failed: %s", text)
			}
			assertRefreshedJSON(t, text, tc.response)
			allowed = false
			if _, failed := callRefreshedMCP(t, s, tc.item, tc.args, tc.resource); !failed {
				t.Fatal("ungranted call succeeded")
			}
			if calls.Load() != 1 || checks != 2 {
				t.Fatalf("upstream calls = %d, grant checks = %d; want 1, 2", calls.Load(), checks)
			}
		})
	}
}

func TestRefreshedSchemaCrowdStrike(t *testing.T) {
	body := `{"destinationType":"crowdstrike","url":"https://logs.example.com/ingest","token":"mock-ingest-token","compressionFormat":"gzip","uploadPeriodMinutes":5}`
	response := `{"logType":"configuration","destinationType":"crowdstrike","url":"https://logs.example.com/ingest","compressionFormat":"gzip","uploadPeriodMinutes":5}`
	for _, method := range []string{"GET", "PUT"} {
		t.Run(method, func(t *testing.T) {
			tool := "tailscale_get_log_streaming_configuration"
			args := map[string]any{"logType": "configuration"}
			if method == "PUT" {
				tool = "tailscale_set_log_streaming_configuration"
				args["body"] = json.RawMessage(body)
				args["confirm"] = "setLogStreamingConfiguration"
			}
			var calls atomic.Int64
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != method || r.URL.Path != "/tailnet/example.com/logging/configuration/stream" || r.URL.RawQuery != "" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
				}
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if method == "PUT" {
					assertRefreshedJSON(t, string(data), body)
				} else if len(data) != 0 {
					t.Errorf("unexpected request body: %s", data)
				}
				_, _ = io.WriteString(w, response)
			}))
			defer api.Close()
			s := server.NewMCPServer("test", "test")
			checks := 0
			RegisterTools(s, Client{Tailnet: "example.com", BaseURL: api.URL, HTTPClient: api.Client()}, func(_ context.Context, item string) error {
				checks++
				if item != tool {
					t.Errorf("grant = %q, want %q", item, tool)
				}
				return nil
			})
			text, failed := callRefreshedMCP(t, s, tool, args, false)
			if failed {
				t.Fatalf("call failed: %s", text)
			}
			assertRefreshedJSON(t, text, response)
			if calls.Load() != 1 || checks != 1 {
				t.Fatalf("upstream calls = %d, grant checks = %d; want 1, 1", calls.Load(), checks)
			}
		})
	}
}

func TestRefreshedSchemaAuditValues(t *testing.T) {
	events := []string{
		"GROUP.UPDATE.USER_ROLE",
		"PAM_CONNECTOR.CREATE", "PAM_CONNECTOR.CREATE.ACCESS_TOKEN", "PAM_CONNECTOR.DELETE", "PAM_CONNECTOR.DISABLE.ACCESS_TOKEN", "PAM_CONNECTOR.UPDATE",
		"PAM_SERVICE.CREATE", "PAM_SERVICE.DELETE", "PAM_SERVICE.UPDATE",
		"PAM_SERVICE_ACCOUNT.CREATE", "PAM_SERVICE_ACCOUNT.CREATE.ACCESS_TOKEN", "PAM_SERVICE_ACCOUNT.DELETE", "PAM_SERVICE_ACCOUNT.UPDATE",
		"PAM_SETTINGS.CREATE.CUSTOM_DOMAIN", "PAM_SETTINGS.CREATE.NOTIFICATION", "PAM_SETTINGS.CREATE.RECORDING_STORAGE",
		"PAM_SETTINGS.DELETE.CUSTOM_DOMAIN", "PAM_SETTINGS.DELETE.NOTIFICATION", "PAM_SETTINGS.DELETE.RECORDING_STORAGE",
		"PAM_SETTINGS.UPDATE", "PAM_SETTINGS.UPDATE.CUSTOM_DOMAIN", "PAM_SETTINGS.UPDATE.NOTIFICATION", "PAM_SETTINGS.UPDATE.SETUP_WIZARD",
	}
	for _, event := range events {
		t.Run(event, func(t *testing.T) {
			response := fmt.Sprintf(`{"logs":[{"event":%q,"origin":"BORDER0_API","actor":{"id":"connector-1","type":"PAM_CONNECTOR","displayName":"Connector"}},{"event":%q,"origin":"BORDER0_API","actor":{"id":"account-1","type":"PAM_SERVICE_ACCOUNT","displayName":"Service account"}}]}`, event, event)
			query := url.Values{"start": {"2026-10-02T00:00:00Z"}, "end": {"2026-10-02T01:00:00Z"}, "event": {event}}
			var calls atomic.Int64
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" || r.URL.Path != "/tailnet/example.com/logging/configuration" || !reflect.DeepEqual(r.URL.Query(), query) {
					t.Errorf("unexpected audit request: %s %s; want query %s", r.Method, r.URL, query.Encode())
				}
				_, _ = io.WriteString(w, response)
			}))
			defer api.Close()
			s := server.NewMCPServer("test", "test")
			checks := 0
			RegisterTools(s, Client{Tailnet: "example.com", BaseURL: api.URL, HTTPClient: api.Client()}, func(_ context.Context, item string) error {
				checks++
				if item != "tailscale_list_configuration_audit_logs" {
					t.Errorf("unexpected audit grant: %q", item)
				}
				return nil
			})
			args := map[string]any{"start": query.Get("start"), "end": query.Get("end"), "event": event}
			text, failed := callRefreshedMCP(t, s, "tailscale_list_configuration_audit_logs", args, false)
			if failed {
				t.Fatalf("call failed: %s", text)
			}
			assertRefreshedJSON(t, text, response)
			if calls.Load() != 1 || checks != 1 {
				t.Fatalf("upstream calls = %d, grant checks = %d; want 1, 1", calls.Load(), checks)
			}
		})
	}
}

func TestRefreshedSchemaAuthorizationFailures(t *testing.T) {
	for _, tc := range []struct {
		tool, confirm, path, parameter string
		status                         int
	}{
		{"tailscale_authorize_device", "authorizeDevice", "/device/id-1/authorized", "deviceId", 400},
		{"tailscale_authorize_device", "authorizeDevice", "/device/id-1/authorized", "deviceId", 402},
		{"tailscale_approve_user", "approveUser", "/users/id-1/approve", "userId", 402},
	} {
		for _, field := range []string{"message", "error"} {
			t.Run(fmt.Sprintf("%s/%d/%s", tc.confirm, tc.status, field), func(t *testing.T) {
				const message = "request rejected by account restrictions"
				var calls atomic.Int64
				api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Method != "POST" || r.URL.Path != tc.path || r.URL.RawQuery != "" {
						t.Errorf("unexpected request: %s %s", r.Method, r.URL)
					}
					if r.Header.Get("Authorization") != "Bearer mock-api-token" {
						t.Error("configured credential not forwarded")
					}
					data, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
					}
					if tc.confirm == "authorizeDevice" {
						assertRefreshedJSON(t, string(data), `{"authorized":true}`)
					} else if len(data) != 0 {
						t.Errorf("approveUser sent unexpected body: %s", data)
					}
					w.WriteHeader(tc.status)
					_, _ = fmt.Fprintf(w, `{"%s":%q,"authorization":"Bearer mock-api-token","oauthClient":{"secret":"mock-oauth-secret"},"unrelated":"private-debug-data"}`, field, message)
				}))
				defer api.Close()
				s := server.NewMCPServer("test", "test")
				checks := 0
				RegisterTools(s, Client{Token: "mock-api-token", BaseURL: api.URL, HTTPClient: api.Client()}, func(_ context.Context, item string) error {
					checks++
					if item != tc.tool {
						t.Errorf("grant = %q, want %q", item, tc.tool)
					}
					return nil
				})
				args := map[string]any{tc.parameter: "id-1"}
				if tc.confirm == "authorizeDevice" {
					args["body"] = map[string]any{"authorized": true}
				}
				for _, confirm := range []string{"", "wrongOperation"} {
					if confirm != "" {
						args["confirm"] = confirm
					}
					text, failed := callRefreshedMCP(t, s, tc.tool, args, false)
					if !failed || !strings.Contains(text, "confirmation required: set confirm to "+tc.confirm) {
						t.Fatalf("invalid confirmation returned failed=%v: %s", failed, text)
					}
					if calls.Load() != 0 {
						t.Fatal("invalid confirmation reached upstream")
					}
				}
				args["confirm"] = tc.confirm
				text, failed := callRefreshedMCP(t, s, tc.tool, args, false)
				want := fmt.Sprintf("tailscale API error %d: %s", tc.status, message)
				if !failed || text != want {
					t.Fatalf("failure = %v, text = %q; want sanitized failure %q", failed, text, want)
				}
				if calls.Load() != 1 || checks == 0 {
					t.Fatalf("upstream calls = %d, grant checks = %d; want one call and authorization", calls.Load(), checks)
				}
			})
		}
	}
}

func callRefreshedMCP(t *testing.T, s *server.MCPServer, item string, args map[string]any, resource bool) (string, bool) {
	t.Helper()
	method := "tools/call"
	params := map[string]any{"name": item, "arguments": args}
	if resource {
		method = "resources/read"
		params = map[string]any{"uri": item}
	}
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	response := s.HandleMessage(context.Background(), raw)
	if rpcErr, ok := response.(mcp.JSONRPCError); ok && resource {
		return rpcErr.Error.Message, true
	}
	rpc, ok := response.(mcp.JSONRPCResponse)
	if !ok {
		t.Fatalf("unexpected MCP response: %#v", response)
	}
	if resource {
		result, ok := rpc.Result.(mcp.ReadResourceResult)
		if !ok || len(result.Contents) != 1 {
			t.Fatalf("unexpected resource result: %#v", rpc.Result)
		}
		content, ok := result.Contents[0].(mcp.TextResourceContents)
		if !ok || content.URI != item || content.MIMEType != "application/json" {
			t.Fatalf("unexpected resource content: %#v", result.Contents[0])
		}
		return content.Text, false
	}
	result, ok := rpc.Result.(*mcp.CallToolResult)
	if !ok || len(result.Content) != 1 {
		t.Fatalf("unexpected tool result: %#v", rpc.Result)
	}
	content, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected tool content: %#v", result.Content[0])
	}
	return content.Text, result.IsError
}

func assertRefreshedJSON(t *testing.T, got, want string) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal([]byte(got), &gotValue); err != nil {
		t.Errorf("invalid actual JSON %q: %v", got, err)
		return
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Errorf("invalid expected JSON %q: %v", want, err)
		return
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("JSON = %s, want %s", got, want)
	}
}
