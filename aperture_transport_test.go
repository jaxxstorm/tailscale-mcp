package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaxxstorm/tailscale-mcp/internal/aperture"
	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"
	"tailscale.com/client/tailscale/apitype"
	tsapi "tailscale.com/client/tailscale/v2"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

type apertureTransportFixture struct {
	peer, local *httptest.Server
	grant       atomic.Value // Raw WhoIs capability, replaced between requests.
	apiCalls    atomic.Int64
	whoIsCalls  atomic.Int64
}

// These tests exercise sessions, which newer MCP protocol versions retire.
const sessionProtocolVersion = "2025-03-26"

func newApertureTransportFixture(t *testing.T, localCaps *MCPCapability, tailscaleEnabled, apertureEnabled bool) *apertureTransportFixture {
	t.Helper()
	oldLogger := logger
	logger = zap.NewNop()
	t.Cleanup(func() { logger = oldLogger })
	f := &apertureTransportFixture{}
	f.grant.Store(`{"tools":["*"],"resources":["*"]}`)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.apiCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/aperture/config":
			w.Header().Set("ETag", `"test"`)
			fmt.Fprint(w, `{"config":"{}"}`)
		case "/aperture/pricing":
			fmt.Fprint(w, `{"models":{}}`)
		case "/tailnet/test/dns/configuration":
			fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)
	var tsHTTP http.Handler
	if tailscaleEnabled {
		base, _ := url.Parse(api.URL)
		ts, _, err := newConfiguredMCPServer(&tsapi.Client{BaseURL: base, HTTP: api.Client(), Tailnet: "test"}, readapi.Client{BaseURL: api.URL, HTTPClient: api.Client(), Tailnet: "test"}, false)
		if err != nil {
			t.Fatal(err)
		}
		tsHTTP = server.NewStreamableHTTPServer(ts, server.WithEndpointPath(mcpEndpointPath))
	}
	var apHTTP http.Handler
	if apertureEnabled {
		client, err := aperture.NewClient(api.URL+"/aperture", api.Client().Transport)
		if err != nil {
			t.Fatal(err)
		}
		ap, _, err := newApertureMCPServer(client)
		if err != nil {
			t.Fatal(err)
		}
		apHTTP = server.NewStreamableHTTPServer(ap, server.WithEndpointPath(apertureEndpointPath))
	}
	peerHandler := mcpHTTPHandler(tsHTTP, apHTTP, func(next http.Handler) http.Handler {
		peer := peerGrantMiddleware(next, func(_ context.Context, addr string) (*apitype.WhoIsResponse, error) {
			f.whoIsCalls.Add(1)
			if _, _, err := net.SplitHostPort(addr); err != nil {
				t.Errorf("WhoIs did not receive peer address: %q", addr)
			}
			raw := f.grant.Load().(string)
			if raw == "unverified" {
				return nil, fmt.Errorf("identity unavailable")
			}
			who := &apitype.WhoIsResponse{}
			if raw != "" {
				who.CapMap = tailcfg.PeerCapMap{mcpCapabilityKey: {tailcfg.RawMessage(raw)}}
			}
			return who, nil
		})
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Existing local identity must never survive the trusted peer lookup.
			peer.ServeHTTP(w, r.WithContext(withCapabilities(r.Context(), localCaps, "local-http")))
		})
	})
	f.peer = httptest.NewUnstartedServer(peerHandler)
	port := f.peer.Listener.Addr().(*net.TCPAddr).Port
	var err error
	f.peer.Config.Handler, err = tailnetHostMiddleware(peerHandler, &ipnstate.Status{TailscaleIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}, port, false)
	if err != nil {
		t.Fatal(err)
	}
	f.peer.Start()
	t.Cleanup(f.peer.Close)
	if err := validateLocalHTTP(true, false, localCaps); err != nil {
		t.Fatal(err)
	}
	f.local = httptest.NewServer(mcpHTTPHandler(tsHTTP, apHTTP, func(next http.Handler) http.Handler {
		return localGrantMiddleware(next, localCaps)
	}))
	t.Cleanup(f.local.Close)
	for _, s := range []*httptest.Server{f.peer, f.local} {
		s.Client().Timeout = 5 * time.Second
		s.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return f
}

func apertureTransportRPC(t *testing.T, s *httptest.Server, path, session, method string, params any) (int, string, map[string]json.RawMessage) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, s.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Origin", s.URL)
	req.Header.Set("Mcp-Session-Id", session)
	req.Header.Set("MCP-Protocol-Version", sessionProtocolVersion)
	req.Header.Set("X-Tailscale-Capabilities", `{"tools":["*"],"resources":["*"]}`)
	req.Header.Set("X-Tailscale-User", "admin")
	res, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var response map[string]json.RawMessage
	if res.StatusCode == http.StatusOK {
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			t.Fatal(err)
		}
	}
	return res.StatusCode, res.Header.Get("Mcp-Session-Id"), response
}

func apertureTransportInitialize(t *testing.T, s *httptest.Server, path string) string {
	t.Helper()
	status, session, response := apertureTransportRPC(t, s, path, "", "initialize", map[string]any{"protocolVersion": sessionProtocolVersion, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "aperture-transport-test", "version": "1"}})
	if status != http.StatusOK || response["error"] != nil || !bytes.Contains(response["result"], []byte(`"serverInfo"`)) || session == "" {
		t.Fatalf("initialize %s: status=%d session=%q response=%s", path, status, session, response)
	}
	return session
}

func apertureTransportResult(t *testing.T, s *httptest.Server, path, session, method string, params any, result any) {
	t.Helper()
	status, _, response := apertureTransportRPC(t, s, path, session, method, params)
	if status != http.StatusOK || response["error"] != nil {
		t.Fatalf("%s %s: status=%d response=%s", path, method, status, response)
	}
	if err := json.Unmarshal(response["result"], result); err != nil {
		t.Fatalf("%s: %v: %s", method, err, response)
	}
}

func TestApertureTransportDisabled(t *testing.T) {
	f := newApertureTransportFixture(t, &MCPCapability{Tools: []string{"*"}}, true, false)
	for _, listener := range []struct {
		name string
		s    *httptest.Server
	}{{"tailnet", f.peer}, {"loopback", f.local}} {
		t.Run(listener.name, func(t *testing.T) {
			before := f.apiCalls.Load()
			status, _, _ := apertureTransportRPC(t, listener.s, apertureEndpointPath, "", "initialize", map[string]any{})
			if status != http.StatusNotFound || f.apiCalls.Load() != before {
				t.Fatalf("disabled Aperture: status=%d backend calls=%d", status, f.apiCalls.Load()-before)
			}
			session := apertureTransportInitialize(t, listener.s, mcpEndpointPath)
			for _, path := range []string{mcpEndpointPath, legacyMCPEndpointPath} {
				var tools mcp.ListToolsResult
				apertureTransportResult(t, listener.s, path, session, "tools/list", map[string]any{}, &tools)
				if len(tools.Tools) == 0 {
					t.Fatal("disabled Aperture removed Tailscale tools")
				}
				for _, tool := range tools.Tools {
					if strings.HasPrefix(tool.Name, "aperture_") {
						t.Fatalf("disabled tool advertised: %s", tool.Name)
					}
				}
				var result mcp.CallToolResult
				apertureTransportResult(t, listener.s, path, session, "tools/call", map[string]any{"name": "tailscale_get_dns_configuration"}, &result)
				if result.IsError {
					t.Fatalf("Tailscale call failed on %s", path)
				}
			}
			if f.apiCalls.Load() != before+2 {
				t.Fatalf("backend calls=%d, want 2", f.apiCalls.Load()-before)
			}
		})
	}
}

func TestApertureTransportTailscaleDisabled(t *testing.T) {
	for _, apertureEnabled := range []bool{false, true} {
		t.Run(fmt.Sprint("aperture=", apertureEnabled), func(t *testing.T) {
			f := newApertureTransportFixture(t, &MCPCapability{Tools: []string{"*"}}, false, apertureEnabled)
			for _, listener := range []struct {
				name string
				s    *httptest.Server
			}{{"tailnet", f.peer}, {"loopback", f.local}} {
				t.Run(listener.name, func(t *testing.T) {
					before, whoBefore := f.apiCalls.Load(), f.whoIsCalls.Load()
					for _, path := range []string{mcpEndpointPath, legacyMCPEndpointPath} {
						status, _, _ := apertureTransportRPC(t, listener.s, path, "", "initialize", map[string]any{})
						if status != http.StatusNotFound {
							t.Fatalf("disabled Tailscale route %s: status=%d", path, status)
						}
					}
					if f.apiCalls.Load() != before || f.whoIsCalls.Load() != whoBefore {
						t.Fatal("disabled route performed backend or identity lookup")
					}
					if !apertureEnabled {
						status, _, _ := apertureTransportRPC(t, listener.s, apertureEndpointPath, "", "initialize", map[string]any{})
						if status != http.StatusNotFound {
							t.Fatalf("both services disabled: status=%d", status)
						}
						return
					}
					session := apertureTransportInitialize(t, listener.s, apertureEndpointPath)
					var tools mcp.ListToolsResult
					apertureTransportResult(t, listener.s, apertureEndpointPath, session, "tools/list", map[string]any{}, &tools)
					if len(tools.Tools) != 5 {
						t.Fatalf("Aperture-only tools=%v", tools.Tools)
					}
					for _, tool := range tools.Tools {
						if !strings.HasPrefix(tool.Name, "aperture_") {
							t.Fatalf("disabled service tool advertised: %s", tool.Name)
						}
					}
					var result mcp.CallToolResult
					apertureTransportResult(t, listener.s, apertureEndpointPath, session, "tools/call", map[string]any{"name": "aperture_get_config", "arguments": map[string]any{}}, &result)
					if result.IsError || f.apiCalls.Load() != before+1 {
						t.Fatalf("Aperture-only call failed: %+v, backend calls=%d", result, f.apiCalls.Load()-before)
					}
					status, _, response := apertureTransportRPC(t, listener.s, apertureEndpointPath, session, "tools/call", map[string]any{"name": "tailscale_get_dns_configuration"})
					if status != http.StatusOK || response["error"] == nil || f.apiCalls.Load() != before+1 {
						t.Fatalf("Tailscale call accepted on Aperture: %d %s", status, response)
					}
				})
			}
		})
	}
}

func TestApertureTransportRouteIsolation(t *testing.T) {
	f := newApertureTransportFixture(t, &MCPCapability{Tools: []string{"*"}, Resources: []string{"*"}}, true, true)
	for _, listener := range []struct {
		name string
		s    *httptest.Server
	}{{"tailnet", f.peer}, {"loopback", f.local}} {
		t.Run(listener.name, func(t *testing.T) {
			s := listener.s
			sessions := map[string]string{}
			for _, path := range []string{mcpEndpointPath, legacyMCPEndpointPath, apertureEndpointPath} {
				sessions[path] = apertureTransportInitialize(t, s, path)
				var tools mcp.ListToolsResult
				apertureTransportResult(t, s, path, sessions[path], "tools/list", map[string]any{}, &tools)
				if len(tools.Tools) == 0 || (path == apertureEndpointPath && len(tools.Tools) != 5) {
					t.Fatalf("unexpected tools on %s: %v", path, tools.Tools)
				}
				for _, tool := range tools.Tools {
					if strings.HasPrefix(tool.Name, "aperture_") != (path == apertureEndpointPath) {
						t.Errorf("cross-service discovery on %s: %s", path, tool.Name)
					}
				}
				for _, method := range []string{"resources/list", "resources/templates/list", "prompts/list"} {
					status, _, response := apertureTransportRPC(t, s, path, sessions[path], method, map[string]any{})
					if status != http.StatusOK {
						t.Fatalf("%s %s: status=%d", path, method, status)
					}
					// An unregistered capability may be unsupported rather than an empty list.
					if response["error"] != nil && path == apertureEndpointPath {
						continue
					}
					var lists map[string][]json.RawMessage
					if response["error"] != nil || json.Unmarshal(response["result"], &lists) != nil {
						t.Fatalf("%s %s: %s", path, method, response)
					}
					count := 0
					for _, entries := range lists {
						count += len(entries)
					}
					if (count > 0) != (path != apertureEndpointPath) {
						t.Fatalf("%s %s unexpected surface: %s", path, method, response)
					}
				}
			}
			if sessions[mcpEndpointPath] == sessions[apertureEndpointPath] {
				t.Fatal("services issued the same session ID")
			}
			before := f.apiCalls.Load()
			for _, tc := range []struct {
				path, method string
				params       any
			}{
				{mcpEndpointPath, "tools/call", map[string]any{"name": "aperture_get_config", "arguments": map[string]any{}}},
				{legacyMCPEndpointPath, "tools/call", map[string]any{"name": "aperture_get_config", "arguments": map[string]any{}}},
				{apertureEndpointPath, "tools/call", map[string]any{"name": "tailscale_get_dns_configuration", "arguments": map[string]any{}}},
				{apertureEndpointPath, "resources/read", map[string]any{"uri": "tailscale://devices"}},
				{apertureEndpointPath, "resources/read", map[string]any{"uri": "bootstrap://status"}},
				{apertureEndpointPath, "prompts/get", map[string]any{"name": "empty"}},
			} {
				status, _, response := apertureTransportRPC(t, s, tc.path, sessions[tc.path], tc.method, tc.params)
				if status != http.StatusOK || response["error"] == nil {
					t.Fatalf("cross-service operation accepted: %+v: %d %s", tc, status, response)
				}
			}
			if f.apiCalls.Load() != before {
				t.Fatal("denied operation contacted backend")
			}
			// Both Tailscale paths use the same SDK handler, including its sessions.
			for _, pair := range [][2]string{{mcpEndpointPath, legacyMCPEndpointPath}, {legacyMCPEndpointPath, mcpEndpointPath}} {
				var result mcp.CallToolResult
				apertureTransportResult(t, s, pair[0], sessions[pair[1]], "tools/call", map[string]any{"name": "tailscale_get_dns_configuration"}, &result)
				if result.IsError {
					t.Fatal("Tailscale session did not work across aliases")
				}
			}
			before = f.apiCalls.Load()
			for _, path := range []string{mcpEndpointPath, apertureEndpointPath} {
				other := apertureEndpointPath
				if path == apertureEndpointPath {
					other = mcpEndpointPath
				}
				status, _, response := apertureTransportRPC(t, s, path, sessions[other], "tools/list", map[string]any{})
				// The SDK can reject a foreign ID or process it without attaching source state.
				if status == http.StatusNotFound {
					continue
				}
				var tools mcp.ListToolsResult
				if status != http.StatusOK || response["error"] != nil || json.Unmarshal(response["result"], &tools) != nil || len(tools.Tools) == 0 {
					t.Fatalf("foreign session: %d %s", status, response)
				}
				for _, tool := range tools.Tools {
					if strings.HasPrefix(tool.Name, "aperture_") != (path == apertureEndpointPath) {
						t.Fatal("foreign session attached source catalog")
					}
				}
				if listener.name == "tailnet" {
					f.grant.Store("")
					apertureTransportResult(t, s, path, sessions[other], "tools/list", map[string]any{}, &tools)
					if len(tools.Tools) != 0 {
						t.Fatal("foreign session transferred permissions")
					}
					name := "tailscale_get_dns_configuration"
					if path == apertureEndpointPath {
						name = "aperture_get_config"
					}
					status, _, response = apertureTransportRPC(t, s, path, sessions[other], "tools/call", map[string]any{"name": name, "arguments": map[string]any{}})
					if status != http.StatusOK || response["error"] == nil || f.apiCalls.Load() != before {
						t.Fatalf("foreign session authorized direct call: %d %s", status, response)
					}
					f.grant.Store(`{"tools":["*"],"resources":["*"]}`)
				}
			}
		})
	}
}

func TestApertureTransportRequestGrants(t *testing.T) {
	f := newApertureTransportFixture(t, &MCPCapability{Tools: []string{"tailscale_get_dns_configuration", "aperture_get_config"}}, true, true)
	for _, tc := range []struct{ path, tool string }{{mcpEndpointPath, "tailscale_get_dns_configuration"}, {legacyMCPEndpointPath, "tailscale_get_dns_configuration"}, {apertureEndpointPath, "aperture_get_config"}} {
		t.Run(tc.path, func(t *testing.T) {
			f.grant.Store(`{"tools":["*"]}`)
			session := apertureTransportInitialize(t, f.local, tc.path)
			for _, grant := range []string{`{"tools":["` + tc.tool + `"]}`, "", `{"tools":["group:unknown"]}`, `{"tools":["` + tc.tool + `"]}`, `{"tools":"*"}`, "unverified"} {
				f.grant.Store(grant)
				before := f.apiCalls.Load()
				status, _, response := apertureTransportRPC(t, f.peer, tc.path, session, "tools/list", map[string]any{})
				wantStatus := http.StatusOK
				if grant == `{"tools":"*"}` {
					wantStatus = http.StatusForbidden
				} else if grant == "unverified" {
					wantStatus = http.StatusUnauthorized
				}
				allowed := strings.Contains(grant, tc.tool)
				if status != wantStatus {
					t.Fatalf("grant %q: status=%d want=%d", grant, status, wantStatus)
				}
				if status == http.StatusOK {
					var tools mcp.ListToolsResult
					if response["error"] != nil || json.Unmarshal(response["result"], &tools) != nil || (len(tools.Tools) == 1) != allowed || len(tools.Tools) > 1 {
						t.Fatalf("session retained grants: %s", response)
					}
				}
				status, _, response = apertureTransportRPC(t, f.peer, tc.path, session, "tools/call", map[string]any{"name": tc.tool, "arguments": map[string]any{}})
				if status != wantStatus {
					t.Fatalf("direct call status=%d want=%d", status, wantStatus)
				}
				if allowed {
					var result mcp.CallToolResult
					if response["error"] != nil || json.Unmarshal(response["result"], &result) != nil || result.IsError || f.apiCalls.Load() != before+1 {
						t.Fatalf("allowed call failed: %s", response)
					}
				} else if f.apiCalls.Load() != before || (status == http.StatusOK && response["error"] == nil) {
					t.Fatalf("denied call dispatched: %s", response)
				}
				// The same session on loopback uses only operator grants, even after peer denial.
				whoIsBefore := f.whoIsCalls.Load()
				var localTools mcp.ListToolsResult
				apertureTransportResult(t, f.local, tc.path, session, "tools/list", map[string]any{}, &localTools)
				if len(localTools.Tools) != 1 || localTools.Tools[0].Name != tc.tool || f.whoIsCalls.Load() != whoIsBefore {
					t.Fatal("loopback discovery used peer grants or spoofed headers")
				}
				name := "tailscale_set_dns_configuration"
				args := map[string]any{"body": map[string]any{}, "confirm": "setDnsConfiguration"}
				if tc.path == apertureEndpointPath {
					name = "aperture_set_config"
					args = map[string]any{"config": "{}", "if_match": `"test"`, "confirm": name}
				}
				before = f.apiCalls.Load()
				for _, s := range []*httptest.Server{f.peer, f.local} {
					status, _, response := apertureTransportRPC(t, s, tc.path, session, "tools/call", map[string]any{"name": name, "arguments": args})
					want := wantStatus
					if s == f.local {
						want = http.StatusOK
					}
					if status != want || (status == http.StatusOK && response["error"] == nil) || f.apiCalls.Load() != before {
						t.Fatalf("ungranted mutation with valid inputs dispatched: %d %s", status, response)
					}
				}
			}
		})
	}
}

func TestApertureTransportProtections(t *testing.T) {
	f := newApertureTransportFixture(t, &MCPCapability{Tools: []string{"*"}}, true, true)
	for _, s := range []*httptest.Server{f.peer, f.local} {
		for _, path := range []string{mcpEndpointPath, legacyMCPEndpointPath, apertureEndpointPath} {
			for _, variant := range []string{"host", "origin", "length", "chunked"} {
				t.Run(s.URL+path+"/"+variant, func(t *testing.T) {
					body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"aperture_get_config","arguments":{}}}`
					want := http.StatusForbidden
					if variant == "length" || variant == "chunked" {
						body += strings.Repeat(" ", int(maxMCPBodyBytes))
						want = http.StatusRequestEntityTooLarge
					}
					req, err := http.NewRequest(http.MethodPost, s.URL+path, strings.NewReader(body))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Accept", "application/json, text/event-stream")
					if variant == "host" {
						req.Host = "attacker.example"
						req.Header.Set("Origin", "http://attacker.example")
						req.Header.Set("X-Forwarded-Host", strings.TrimPrefix(s.URL, "http://"))
					} else if variant == "origin" {
						req.Header.Set("Origin", "https://"+req.URL.Host)
						req.Header.Set("X-Forwarded-Proto", "https")
					} else if variant == "chunked" {
						req.ContentLength = -1
					}
					before := f.apiCalls.Load()
					res, err := s.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					_, _ = io.Copy(io.Discard, res.Body)
					res.Body.Close()
					if res.StatusCode != want || f.apiCalls.Load() != before {
						t.Fatalf("protection failed: status=%d want=%d calls=%d", res.StatusCode, want, f.apiCalls.Load()-before)
					}
				})
			}
			apertureTransportInitialize(t, s, path)
		}
	}
}
