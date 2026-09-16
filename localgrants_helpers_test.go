package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestStrictLocalGrantConfiguration(t *testing.T) {
	for _, raw := range []string{"", " ", "{}", `{"tools":[],"resources":[]}`, `{"tools":["get_device_info"],"resources":["tailscale://devices/*"]}`} {
		if _, err := parseLocalGrants(raw); err != nil {
			t.Errorf("%q: %v", raw, err)
		}
	}
	for _, raw := range []string{"null", "[]", `{"Tools":["*"]}`, `{"unknown":[]}`, `{"tools":"*"}`, `{"tools":null}`, `{"tools":[null]}`, `{"tools":[1]}`, `{"tools":[],"tools":["*"]}`, `{} {}`, `{"tools":[]`, `{"tools":[],}`} {
		if _, err := parseLocalGrants(raw); err == nil {
			t.Errorf("accepted invalid grant %q", raw)
		}
	}
	for _, raw := range []string{"", "{}", `{"tools":[]}`, `{"tools":[" ",""]}`} {
		caps, _ := parseLocalGrants(raw)
		if err := validateLocalHTTP(true, false, caps); err == nil {
			t.Errorf("accepted empty local grant %q", raw)
		}
	}
	caps, _ := parseLocalGrants(`{"tools":["get_device_info"]}`)
	if err := validateLocalHTTP(false, false, caps); err != nil {
		t.Fatal(err)
	}
	if err := validateLocalHTTP(true, false, caps); err != nil {
		t.Fatal(err)
	}
	if err := validateLocalHTTP(true, true, caps); err == nil {
		t.Fatal("accepted stdio/local HTTP conflict")
	}
}

func TestStdioLocalContext(t *testing.T) {
	caps := &MCPCapability{Tools: []string{"get_device_info"}}
	ctx := stdioContextFunc(caps)(context.Background())
	got, user, err := getTailscaleCapabilities(ctx)
	if err != nil || got == nil || len(got.Tools) != 1 || got.Tools[0] != "get_device_info" || user != "local-stdio" {
		t.Fatalf("local context = %+v %q %v", got, user, err)
	}
	ctx = stdioContextFunc(nil)(context.Background())
	got, _, _ = getTailscaleCapabilities(ctx)
	if got != nil && (len(got.Tools) != 0 || len(got.Resources) != 0) {
		t.Fatal("absent grant gained permissions")
	}
}

func TestLocalHostProtectionSDKStack(t *testing.T) {
	caps := &MCPCapability{Tools: []string{"get_device_info"}}
	mcpServer := server.NewMCPServer("transport-test", "test")
	sdk := server.NewStreamableHTTPServer(mcpServer)
	handler := strictOriginMiddleware(bodyLimitMiddleware(localGrantMiddleware(sdk, caps), 0))
	s := httptest.NewServer(handler)
	defer s.Close()
	for _, origin := range []string{"", "http://attacker.example"} {
		req, _ := http.NewRequest("POST", s.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`))
		req.Host = "attacker.example"
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		res, err := s.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("origin %q: status %d", origin, res.StatusCode)
		}
	}
	// A real loopback initialization still reaches the SDK.
	req, _ := http.NewRequest("POST", s.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "serverInfo") {
		t.Fatalf("local initialization: %d %s", res.StatusCode, body)
	}
}

func TestLocalGrantsIgnoreSpoofedHeadersAndContext(t *testing.T) {
	caps := &MCPCapability{Tools: []string{"get_device_info"}}
	h := localGrantMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, user, err := getTailscaleCapabilities(r.Context())
		if err != nil || got == nil || len(got.Tools) != 1 || got.Tools[0] != "get_device_info" || len(got.Resources) != 0 || user != "local-http" {
			t.Errorf("spoofed identity/grants: %+v %q %v", got, user, err)
		}
		w.WriteHeader(204)
	}), caps)
	r := httptest.NewRequest("POST", "http://localhost:8080/mcp", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Tailscale-User", "admin")
	r.Header.Set("X-Tailscale-Capabilities", `{"tools":["*"]}`)
	r.Header.Set("X-Forwarded-For", "100.64.0.1")
	r = r.WithContext(withCapabilities(r.Context(), &MCPCapability{Tools: []string{"*"}}, "spoof"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("status %d", w.Code)
	}
	r.RemoteAddr = "100.64.0.1:12345"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("non-loopback peer accepted")
	}
}

func TestGrantlessSDKBodyLimits(t *testing.T) {
	sdk := server.NewStreamableHTTPServer(server.NewMCPServer("body-limit-test", "test"))
	s := httptest.NewServer(strictOriginMiddleware(bodyLimitMiddleware(localGrantMiddleware(sdk, nil), 0)))
	defer s.Close()
	for _, chunked := range []bool{false, true} {
		req, _ := http.NewRequest("POST", s.URL+"/mcp", strings.NewReader(strings.Repeat(" ", int(maxMCPBodyBytes)+1)))
		if chunked {
			req.ContentLength = -1
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		res, err := s.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("chunked=%v: status %d", chunked, res.StatusCode)
		}
	}
}

func TestStdioLocalGrantProtocol(t *testing.T) {
	for _, permitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "permitted"}[permitted], func(t *testing.T) {
			var caps *MCPCapability
			if permitted {
				caps = &MCPCapability{Tools: []string{"probe"}}
			}
			var calls atomic.Int32
			m := server.NewMCPServer("stdio-test", "test")
			m.AddTool(mcp.NewTool("probe"), func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				if err := checkToolAccess(ctx, "probe"); err != nil {
					return mcp.NewToolResultError(err.Error()), nil
				}
				calls.Add(1)
				return mcp.NewToolResultText("permitted"), nil
			})
			m.AddResource(mcp.NewResource("test://private", "private"), func(ctx context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				if err := checkResourceAccess(ctx, "test://private"); err != nil {
					return nil, err
				}
				calls.Add(1)
				return nil, nil
			})
			stdio := server.NewStdioServer(m)
			server.WithStdioContextFunc(stdioContextFunc(caps))(stdio)
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- stdio.Listen(ctx, peer, peer) }()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			enc, dec := json.NewEncoder(client), json.NewDecoder(client)
			request := func(method string, params any) map[string]json.RawMessage {
				t.Helper()
				if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params}); err != nil {
					t.Fatal(err)
				}
				var response map[string]json.RawMessage
				if err := dec.Decode(&response); err != nil {
					t.Fatal(err)
				}
				return response
			}
			response := request("initialize", map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "test", "version": "1"}})
			if response["error"] != nil {
				t.Fatalf("initialize: %s", response["error"])
			}
			response = request("tools/list", map[string]any{})
			if response["error"] != nil {
				t.Fatalf("tools/list: %s", response["error"])
			}
			response = request("tools/call", map[string]any{"name": "probe", "arguments": map[string]any{}})
			var result mcp.CallToolResult
			if err := json.Unmarshal(response["result"], &result); err != nil {
				t.Fatal(err)
			}
			if result.IsError == permitted {
				t.Fatalf("permitted=%v isError=%v", permitted, result.IsError)
			}
			response = request("resources/read", map[string]any{"uri": "test://private"})
			if response["error"] == nil {
				t.Fatal("tool grant authorized resource")
			}
			want := int32(0)
			if permitted {
				want = 1
			}
			if calls.Load() != want {
				t.Fatalf("backend calls=%d want=%d", calls.Load(), want)
			}
			cancel()
			client.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("stdio did not stop")
			}
		})
	}
}
