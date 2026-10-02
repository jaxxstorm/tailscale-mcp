package readapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
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

func lifecycleServer(client Client) *server.MCPServer {
	s := server.NewMCPServer("lifecycle-test", "test")
	RegisterTools(s, client, func(context.Context, string) error { return nil })
	return s
}

func callLifecycle(t *testing.T, s *server.MCPServer, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "tailscale_" + tool, "arguments": args}})
	if err != nil {
		t.Fatal(err)
	}
	response := s.HandleMessage(context.Background(), raw)
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Result *mcp.CallToolResult `json:"result"`
		Error  any                 `json:"error"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Error != nil || decoded.Result == nil {
		t.Fatalf("unexpected RPC response: %s", data)
	}
	return decoded.Result
}

func lifecycleJSON(t *testing.T, result *mcp.CallToolResult) any {
	t.Helper()
	if result.IsError {
		t.Fatalf("unexpected failure: %+v", result)
	}
	var value any
	if err := json.Unmarshal([]byte(result.Content[0].(mcp.TextContent).Text), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestLifecycleSchemas(t *testing.T) {
	s := lifecycleServer(Client{})
	for _, tc := range []struct {
		tool     string
		required []string
	}{
		{"list_organization_tailnets", []string{"organization"}},
		{"create_organization_tailnet", []string{"organization", "body", "confirm"}},
		{"delete_tailnet", []string{"tailnet", "confirm"}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			schema := s.GetTool("tailscale_" + tc.tool).Tool.InputSchema
			if !reflect.DeepEqual(schema.Required, tc.required) {
				t.Fatalf("required = %v", schema.Required)
			}
			data, _ := json.Marshal(schema)
			var decoded map[string]any
			_ = json.Unmarshal(data, &decoded)
			props := decoded["properties"].(map[string]any)
			name := "organization"
			if tc.tool == "delete_tailnet" {
				name = "tailnet"
			}
			p := props[name].(map[string]any)
			if p["type"] != "string" || p["pattern"] != `\S` {
				t.Fatalf("string schema = %v", p)
			}
			if tc.tool == "list_organization_tailnets" {
				limit := props["limit"].(map[string]any)
				if limit["type"] != "integer" || limit["minimum"] != float64(1) || limit["maximum"] != float64(100) {
					t.Fatalf("limit = %v", limit)
				}
				if props["cursor"].(map[string]any)["type"] != "string" {
					t.Fatal("cursor must be a string")
				}
			}
			if tc.tool == "create_organization_tailnet" {
				body := props["body"].(map[string]any)
				if body["type"] != "object" || !reflect.DeepEqual(body["required"], []any{"displayName"}) {
					t.Fatalf("body = %v", body)
				}
				p := body["properties"].(map[string]any)["displayName"].(map[string]any)
				if p["type"] != "string" || p["pattern"] != `\S` {
					t.Fatalf("displayName = %v", p)
				}
			}
		})
	}
	// Opt-in metadata must not retrofit older string parameters or optional bodies.
	old := s.GetTool("tailscale_update_service").Tool.InputSchema
	if !reflect.DeepEqual(old.Required, []string{"serviceName", "confirm"}) {
		t.Fatalf("legacy required = %v", old.Required)
	}
	if old.Properties["serviceName"].(map[string]any)["pattern"] != nil {
		t.Fatal("legacy path schema changed")
	}
}

func TestLifecycleInvalidInputs(t *testing.T) {
	var calls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.WriteString(w, `{}`) }))
	defer api.Close()
	s := lifecycleServer(Client{Tailnet: "configured", BaseURL: api.URL, HTTPClient: api.Client()})
	missing := struct{}{}
	for _, tc := range []struct {
		tool, field string
		base        map[string]any
		invalid     []any
	}{
		{"list_organization_tailnets", "organization", map[string]any{"organization": "org"}, []any{missing, nil, "", " \t\n", 1, true, []any{"org"}}},
		{"list_organization_tailnets", "limit", map[string]any{"organization": "org"}, []any{nil, "1", 1.5, 0, -1, 101, true, []any{1}}},
		{"list_organization_tailnets", "cursor", map[string]any{"organization": "org"}, []any{nil, 1, true, []any{"cursor"}}},
		{"create_organization_tailnet", "organization", map[string]any{"organization": "org", "body": map[string]any{"displayName": "Test"}, "confirm": "createOrganizationTailnet"}, []any{missing, nil, "", " \n", 5}},
		{"create_organization_tailnet", "body", map[string]any{"organization": "org", "confirm": "createOrganizationTailnet"}, []any{missing, nil, "body", 1, []any{}, map[string]any{}, map[string]any{"displayName": nil}, map[string]any{"displayName": ""}, map[string]any{"displayName": " \n"}, map[string]any{"displayName": 42}, map[string]any{"displayName": true}}},
		{"create_organization_tailnet", "confirm", map[string]any{"organization": "org", "body": map[string]any{"displayName": "Test"}}, []any{missing, nil, "", "wrong", 1}},
		{"delete_tailnet", "tailnet", map[string]any{"confirm": "deleteTailnet"}, []any{missing, nil, "", " \n", "-", "other", "Configured", "configured ", 1, true}},
		{"delete_tailnet", "confirm", map[string]any{"tailnet": "configured"}, []any{missing, nil, "", "wrong", 1}},
	} {
		for i, value := range tc.invalid {
			t.Run(fmt.Sprintf("%s/%s/%d", tc.tool, tc.field, i), func(t *testing.T) {
				args := map[string]any{}
				for k, v := range tc.base {
					args[k] = v
				}
				if value != missing {
					args[tc.field] = value
				} else {
					delete(args, tc.field)
				}
				if !callLifecycle(t, s, tc.tool, args).IsError {
					t.Fatal("invalid input accepted")
				}
				// Call the production registered handler directly too: validation cannot rely on SDK schema enforcement.
				req := mcp.CallToolRequest{}
				req.Params.Arguments = args
				result, err := s.GetTool("tailscale_"+tc.tool).Handler(context.Background(), req)
				if err != nil || result == nil || !result.IsError {
					t.Fatalf("handler accepted input: %v, %v", result, err)
				}
				if calls.Load() != 0 {
					t.Fatal("invalid input reached upstream")
				}
			})
		}
	}
	for _, target := range []string{"", " \t", "-"} {
		s := lifecycleServer(Client{Tailnet: target, BaseURL: api.URL, HTTPClient: api.Client()})
		if !callLifecycle(t, s, "delete_tailnet", map[string]any{"tailnet": target, "confirm": "deleteTailnet"}).IsError {
			t.Fatalf("accepted configured target %q", target)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unsafe configured target reached upstream")
	}
}

func TestLifecycleListOnePage(t *testing.T) {
	for _, tc := range []struct {
		org    string
		limit  any
		cursor string
	}{{"org /?#%", 1, "opaque /?&="}, {"org", 100, ""}, {"-", nil, ""}} {
		t.Run(fmt.Sprint(tc.org, tc.limit), func(t *testing.T) {
			var calls atomic.Int64
			response := `{"tailnets":[{"id":"id","displayName":"name","extra":true}],"cursor":"next-page","totalCount":123,"extra":"preserved"}`
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" || r.URL.EscapedPath() != "/organizations/"+url.PathEscape(tc.org)+"/tailnets" {
					t.Errorf("request = %s %s", r.Method, r.URL)
				}
				q := url.Values{}
				if tc.limit != nil {
					q.Set("limit", fmt.Sprint(tc.limit))
				}
				if tc.cursor != "" {
					q.Set("cursor", tc.cursor)
				}
				if r.URL.RawQuery != q.Encode() {
					t.Errorf("query = %s, want %s", r.URL.RawQuery, q.Encode())
				}
				_, _ = io.WriteString(w, response)
			}))
			defer api.Close()
			args := map[string]any{"organization": tc.org}
			if tc.limit != nil {
				args["limit"] = tc.limit
			}
			if tc.cursor != "" {
				args["cursor"] = tc.cursor
			}
			got := lifecycleJSON(t, callLifecycle(t, lifecycleServer(Client{BaseURL: api.URL, HTTPClient: api.Client()}), "list_organization_tailnets", args))
			var want any
			_ = json.Unmarshal([]byte(response), &want)
			if !reflect.DeepEqual(got, want) || calls.Load() != 1 {
				t.Fatalf("result = %v, calls = %d", got, calls.Load())
			}
		})
	}
}

func TestLifecycleCreateAndDelete(t *testing.T) {
	var logs bytes.Buffer
	oldLog, oldSlog := log.Writer(), slog.Default()
	log.SetOutput(&logs)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer func() { slog.SetDefault(oldSlog); log.SetOutput(oldLog) }()
	for _, alreadyExists := range []bool{false, true} {
		var calls atomic.Int64
		response := fmt.Sprintf(`{"id":"id","displayName":"Test","orgId":"org","dnsName":"test.ts.net","createdAt":"2026-10-02T00:00:00Z","oauthClient":{"id":"client","secret":"one-time-secret"},"alreadyExists":%t}`, alreadyExists)
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if r.Header.Get("Authorization") != "Bearer configured-credential" {
				t.Error("configured credential not reused")
			}
			if r.URL.RawQuery != "" {
				t.Error("unexpected query")
			}
			body, _ := io.ReadAll(r.Body)
			switch r.Method {
			case "POST":
				if r.URL.EscapedPath() != "/organizations/org%2Fname/tailnets" || string(body) != `{"displayName":"Test","extra":"forwarded"}` || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("creation request: %s %s", r.URL, body)
				}
				_, _ = io.WriteString(w, response)
			case "DELETE":
				if r.URL.EscapedPath() != "/tailnet/configured%2Ftarget" || len(body) != 0 || r.Header.Get("Content-Type") != "" {
					t.Errorf("deletion request: %s %s", r.URL, body)
				}
				w.WriteHeader(http.StatusOK)
			default:
				t.Errorf("unexpected request (token exchange?): %s %s", r.Method, r.URL)
			}
		}))
		s := lifecycleServer(Client{Tailnet: "configured/target", Token: "configured-credential", BaseURL: api.URL, HTTPClient: api.Client()})
		got := lifecycleJSON(t, callLifecycle(t, s, "create_organization_tailnet", map[string]any{"organization": "org/name", "body": map[string]any{"displayName": "Test", "extra": "forwarded"}, "confirm": "createOrganizationTailnet"}))
		var want any
		_ = json.Unmarshal([]byte(response), &want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("creation response = %v", got)
		}
		got = lifecycleJSON(t, callLifecycle(t, s, "delete_tailnet", map[string]any{"tailnet": "configured/target", "confirm": "deleteTailnet", "body": map[string]any{"ignored": true}}))
		if !reflect.DeepEqual(got, map[string]any{}) || calls.Load() != 2 {
			t.Fatalf("delete result = %v, total calls = %d", got, calls.Load())
		}
		api.Close()
	}
	if strings.Contains(logs.String(), "one-time-secret") || strings.Contains(logs.String(), "configured-credential") {
		t.Fatalf("credentials logged: %s", &logs)
	}
}

type lifecycleTransport func(*http.Request) (*http.Response, error)

func (f lifecycleTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type lifecycleBrokenBody struct{}

func (lifecycleBrokenBody) Read([]byte) (int, error) {
	return 0, errors.New("Authorization: Bearer configured-credential one-time-secret")
}

func (lifecycleBrokenBody) Close() error { return nil }

func TestLifecycleSanitizedFailures(t *testing.T) {
	var logs bytes.Buffer
	oldLog, oldSlog := log.Writer(), slog.Default()
	log.SetOutput(&logs)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer func() { slog.SetDefault(oldSlog); log.SetOutput(oldLog) }()
	for _, endpoint := range ToolEndpoints() {
		if !endpoint.isLifecycle() {
			continue
		}
		for _, tc := range []struct {
			name          string
			status        int
			body, message string
			transport     bool
		}{
			{"forbidden", 403, `{"message":"permission denied","oauthClient":{"secret":"one-time-secret"},"Authorization":"Bearer configured-credential","extra":"private-extra"}`, "permission denied", false},
			{"error-field", 402, `{"error":"billing restriction","extra":"private-extra"}`, "billing restriction", false},
			{"unknown-fields", 500, `{"oauthClient":{"secret":"one-time-secret"}}`, "Internal Server Error", false},
			{"raw-body", 500, `Authorization: Bearer configured-credential one-time-secret`, "Internal Server Error", false},
			{"reflected-secret", 400, `{"message":"invalid one-time-secret","oauthClient":{"secret":"one-time-secret"}}`, "invalid [redacted]", false},
			{"reflected-token", 400, `{"message":"invalid configured-credential"}`, "invalid [redacted]", false},
			{"credential-prose", 400, `{"message":"Authorization: Bearer unknown-secret"}`, "Bad Request", false},
			{"redirect", 307, `{}`, "Temporary Redirect", false},
			{"transport", 0, "", "API request failed; outcome may be unknown", true},
			{"read-failure", 200, "", "failed to read API response; outcome may be unknown", false},
		} {
			t.Run(endpoint.OperationID+"/"+tc.name, func(t *testing.T) {
				calls := 0
				hc := &http.Client{Transport: lifecycleTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if tc.transport {
						return nil, errors.New("Authorization: Bearer configured-credential oauth secret one-time-secret")
					}
					if tc.name == "read-failure" {
						return &http.Response{StatusCode: tc.status, Header: http.Header{}, Body: lifecycleBrokenBody{}, Request: r}, nil
					}
					return &http.Response{StatusCode: tc.status, Header: http.Header{"Location": []string{"https://should-not-follow.invalid"}}, Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
				})}
				s := lifecycleServer(Client{Tailnet: "configured", Token: "configured-credential", BaseURL: "https://mock.invalid", HTTPClient: hc})
				args := map[string]any{"organization": "org", "body": map[string]any{"displayName": "Test"}, "tailnet": "configured", "confirm": endpoint.Confirm}
				result := callLifecycle(t, s, strings.TrimPrefix(endpoint.ToolName, "tailscale_"), args)
				if !result.IsError || calls != 1 {
					t.Fatalf("error=%v, calls=%d", result.IsError, calls)
				}
				data, _ := json.Marshal(result)
				for _, secret := range []string{"configured-credential", "one-time-secret", "private-extra", "Authorization", "Bearer"} {
					if strings.Contains(string(data), secret) || strings.Contains(logs.String(), secret) {
						t.Fatalf("leaked %s in error/log", secret)
					}
				}
				structured := result.StructuredContent.(map[string]any)
				if structured["operation"] != endpoint.OperationID || structured["message"] != tc.message {
					t.Fatalf("error = %v", structured)
				}
				if tc.status != 0 && structured["statusCode"] != float64(tc.status) {
					t.Fatalf("status = %v", structured)
				}
				var text map[string]any
				if err := json.Unmarshal([]byte(result.Content[0].(mcp.TextContent).Text), &text); err != nil || !reflect.DeepEqual(text, structured) {
					t.Fatalf("unstructured text error: %v", result)
				}
			})
		}
	}
}

func TestLifecycleTransportAuthFailure(t *testing.T) {
	const credential = "tskey-api-actual-private-credential"
	var logs bytes.Buffer
	oldLog, oldSlog := log.Writer(), slog.Default()
	log.SetOutput(&logs)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer func() { slog.SetDefault(oldSlog); log.SetOutput(oldLog) }()
	var calls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+credential {
			t.Error("transport credential not sent")
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"message":"invalid %s"}`, credential)
	}))
	defer api.Close()
	base := api.Client().Transport
	hc := &http.Client{Transport: lifecycleTransport(func(r *http.Request) (*http.Response, error) {
		// Production authenticates inside the transport, without setting Client.Token.
		clone := r.Clone(r.Context())
		clone.Header.Set("Authorization", "Bearer "+credential)
		return base.RoundTrip(clone)
	})}
	s := lifecycleServer(Client{Tailnet: "configured", BaseURL: api.URL, HTTPClient: hc})
	for _, endpoint := range ToolEndpoints() {
		if !endpoint.isLifecycle() {
			continue
		}
		t.Run(endpoint.OperationID, func(t *testing.T) {
			before := calls.Load()
			result := callLifecycle(t, s, strings.TrimPrefix(endpoint.ToolName, "tailscale_"), map[string]any{
				"organization": "org", "tailnet": "configured", "confirm": endpoint.Confirm, "body": map[string]any{"displayName": "Test"},
			})
			if !result.IsError || calls.Load() != before+1 {
				t.Fatalf("error=%v, requests=%d", result.IsError, calls.Load()-before)
			}
			data, _ := json.Marshal(result)
			if strings.Contains(string(data), credential) || strings.Contains(logs.String(), credential) {
				t.Fatal("transport credential leaked")
			}
			structured := result.StructuredContent.(map[string]any)
			if structured["operation"] != endpoint.OperationID || structured["statusCode"] != float64(401) || structured["message"] != "Unauthorized" {
				t.Fatalf("unexpected sanitized error: %v", structured)
			}
		})
	}
}

func TestLifecycleInvalidSuccessResponses(t *testing.T) {
	const secret = "private-response-credential"
	var logs bytes.Buffer
	oldLog, oldSlog := log.Writer(), slog.Default()
	log.SetOutput(&logs)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer func() { slog.SetDefault(oldSlog); log.SetOutput(oldLog) }()
	const limit = 4 << 20
	for _, endpoint := range ToolEndpoints() {
		if !endpoint.isLifecycle() {
			continue
		}
		for _, tc := range []struct {
			name, body string
			deleteOK   bool
		}{
			{"empty", "", true},
			{"whitespace", " \n\t", true},
			{"empty-object", `{}`, true},
			{"null", `null`, true},
			{"array", `[]`, true},
			{"string", `"` + secret + `"`, true},
			{"malformed", `{"oauthClient":{"secret":"` + secret + `"}`, false},
			{"trailing-garbage", `{"secret":"` + secret + `"} trailing`, false},
			{"oversized-json", `{"secret":"` + secret + `","padding":"` + strings.Repeat("x", limit) + `"}`, false},
			// A complete JSON prefix must not mask data beyond the size limit.
			{"oversized-whitespace", `{"secret":"` + secret + `"}` + strings.Repeat(" ", limit), false},
		} {
			t.Run(endpoint.OperationID+"/"+tc.name, func(t *testing.T) {
				calls := 0
				hc := &http.Client{Transport: lifecycleTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
				})}
				s := lifecycleServer(Client{Tailnet: "configured", HTTPClient: hc})
				result := callLifecycle(t, s, strings.TrimPrefix(endpoint.ToolName, "tailscale_"), map[string]any{
					"organization": "org", "tailnet": "configured", "confirm": endpoint.Confirm, "body": map[string]any{"displayName": "Test"},
				})
				wantError := endpoint.OperationID != "deleteTailnet" || !tc.deleteOK
				if result.IsError != wantError || calls != 1 {
					t.Fatalf("error=%v, want=%v, calls=%d", result.IsError, wantError, calls)
				}
				if wantError {
					data, _ := json.Marshal(result)
					if strings.Contains(string(data), secret) || strings.Contains(logs.String(), secret) {
						t.Fatal("invalid response credential leaked")
					}
					structured := result.StructuredContent.(map[string]any)
					if structured["operation"] != endpoint.OperationID || structured["statusCode"] != float64(200) || !strings.Contains(structured["message"].(string), "outcome may be unknown") {
						t.Fatalf("unexpected error: %v", structured)
					}
				}
			})
		}
	}
}
