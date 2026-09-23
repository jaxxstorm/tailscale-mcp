package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"
	"tailscale.com/client/tailscale/apitype"
	tsapi "tailscale.com/client/tailscale/v2"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// Reuse the test executable, but invoke the real entry point with application
// arguments. An allowlisted environment and transport keep operator credentials
// and external services out of these startup regressions.
func startupCommand(t *testing.T, mode string, args ...string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, executable, append([]string{"-test.run=^TestStartupIntegrationProcess$", "--"}, args...)...)
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"TS_MCP_STARTUP_TEST=" + mode, "HOME=" + cmd.Dir, "PATH=" + cmd.Dir}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	t.Cleanup(func() {
		if cmd.Process != nil && cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		entries, err := os.ReadDir(cmd.Dir)
		if err != nil || len(entries) != 0 {
			t.Errorf("startup created state in isolated working directory: %v, %v", entries, err)
		}
	})
	return cmd, &stderr
}

func TestStartupIntegrationProcess(t *testing.T) {
	mode := os.Getenv("TS_MCP_STARTUP_TEST")
	if mode == "" {
		return
	}
	if mode == "signals" || mode == "serve-failure" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		var bindings []httpServerListener
		var addresses []string
		for range 2 {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addresses = append(addresses, listener.Addr().String())
			bindings = append(bindings, httpServerListener{newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/stream" {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: ready\n\n")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				w.WriteHeader(http.StatusNoContent)
			})), listener})
		}
		if mode == "serve-failure" {
			bindings[0].Listener = failedTransportListener{bindings[0].Listener, errors.New("startup injected accept failure")}
		}
		_ = json.NewEncoder(os.Stdout).Encode(addresses)
		err := serveHTTPServers(ctx, time.Second, bindings...)
		for _, binding := range bindings {
			if _, closeErr := binding.Listener.Accept(); !errors.Is(closeErr, net.ErrClosed) && mode != "serve-failure" {
				t.Fatalf("listener remained open: %v", closeErr)
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1) // Same return-error-to-exit mapping as main.
		}
		os.Exit(0)
	}
	var apiCalls, validations atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	http.DefaultTransport = credentialRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := "{}"
		if mode != "stdio" && mode != "stdio-context" {
			panic("offline startup attempted HTTP: " + r.URL.String())
		}
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v2/oauth/token":
			body = `{"access_token":"test-only-access-token","token_type":"Bearer","expires_in":3600}`
		case r.Method == "GET" && r.URL.Path == "/api/v2/tailnet/test/settings":
			validations.Add(1)
			if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > credentialValidationTimeout {
				panic("startup validation missing bounded context")
			}
		case (r.Method == "GET" || r.Method == "POST") && r.URL.Path == "/api/v2/tailnet/test/dns/configuration":
			apiCalls.Add(1)
			if mode == "stdio-context" {
				cancel()
			}
		default:
			panic("unexpected startup API request: " + r.Method + " " + r.URL.String())
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"ts-mcp"}, os.Args[i+1:]...)
			break
		}
	}
	if mode == "stdio-context" {
		var cli CLI
		kong.Parse(&cli)
		initLogger(false)
		if err := run(ctx, cli); err != nil {
			t.Fatal(err)
		}
	} else {
		main()
	}
	if mode == "stdio" && validations.Load() != 1 {
		t.Fatalf("startup validation calls=%d, want 1", validations.Load())
	}
	fmt.Fprintf(os.Stderr, "startup API calls: %d\n", apiCalls.Load())
	os.Exit(0)
}

func TestStartupIntegrationCLI(t *testing.T) {
	cliType := reflect.TypeOf(CLI{})
	for i := range cliType.NumField() {
		if key := cliType.Field(i).Tag.Get("env"); key != "" {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		name                              string
		args                              []string
		env                               map[string]string
		port, local                       int
		explicitPort, explicitLocal, fail bool
	}{
		{name: "defaults", port: 8080, local: 8080},
		{name: "TLS flag", args: []string{"--tls", "--local-http"}, port: 443, local: 8080},
		{name: "environment", env: map[string]string{"TS_TLS": "true", "TS_PORT": "8443", "TS_MCP_LOCAL_HTTP": "true", "TS_MCP_LOCAL_PORT": "9090", "TS_MCP_LOCAL_GRANTS": `{"tools":["read:*"]}`}, port: 8443, local: 9090, explicitPort: true, explicitLocal: true},
		{name: "flags override environment", args: []string{"--tls=false", "--port=8081", "--local-http", "--local-port=9091"}, env: map[string]string{"TS_TLS": "true", "TS_PORT": "8443", "TS_MCP_LOCAL_PORT": "9090"}, port: 8081, local: 9091, explicitPort: true, explicitLocal: true},
		{name: "explicit zero flag", args: []string{"--port=0"}, explicitPort: true, fail: true},
		{name: "explicit zero env", env: map[string]string{"TS_PORT": "0"}, explicitPort: true, fail: true},
		{name: "local zero env", env: map[string]string{"TS_MCP_LOCAL_HTTP": "true", "TS_MCP_LOCAL_PORT": "0"}, explicitLocal: true, fail: true},
		{name: "local opt-in required", args: []string{"--local-port=8080"}, explicitLocal: true, fail: true},
		{name: "stdio default port absent", args: []string{"--stdio"}, port: 8080, local: 8080},
		{name: "stdio explicit default conflicts", args: []string{"--stdio", "--port=8080"}, explicitPort: true, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			var cli CLI
			parser, err := kong.New(&cli)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parser.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			if (cli.Port != nil) != tc.explicitPort || (cli.LocalPort != nil) != tc.explicitLocal {
				t.Fatalf("pointer presence lost: port=%v local=%v", cli.Port, cli.LocalPort)
			}
			port, local, err := resolvePorts(cli.Port, cli.LocalPort, cli.TLS, cli.LocalHTTP, cli.Stdio)
			if (err != nil) != tc.fail || (!tc.fail && (port != tc.port || local != tc.local)) {
				t.Fatalf("ports=(%d,%d), err=%v", port, local, err)
			}
			if want := tc.env["TS_MCP_LOCAL_GRANTS"]; cli.LocalGrants != want {
				t.Fatalf("local grants env=%q", cli.LocalGrants)
			}
		})
	}
}

func TestStartupIntegrationOffline(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"--list-groups"}, {"--list-groups", "--local-cli"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var previous []byte
			for range 2 {
				// Invalid serving-only configuration must not block informational commands.
				cmd, stderr := startupCommand(t, "offline", append(args, "--state=invalid://must-not-initialize", "--local-grants={", "--port=0")...)
				output, err := cmd.Output()
				if err != nil {
					t.Fatalf("offline main: %v\n%s", err, stderr)
				}
				if args[0] == "--version" {
					if string(output) != "ts-mcp "+buildVersion+"\n" {
						t.Fatalf("version=%q", output)
					}
				} else {
					var expected bytes.Buffer
					if err := writeToolGroups(&expected, len(args) == 2); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(output, expected.Bytes()) {
						t.Fatal("main group listing differs from configured catalog")
					}
				}
				if previous != nil && !bytes.Equal(previous, output) {
					t.Fatal("nondeterministic offline output")
				}
				previous = output
			}
		})
	}
	cmd, stderr := startupCommand(t, "offline")
	if err := cmd.Run(); err == nil || !strings.Contains(stderr.String(), "TAILSCALE_TAILNET is required") {
		t.Fatalf("serving without configuration: %v %s", err, stderr)
	}
}

func TestStartupIntegrationRejectsLocalConfigBeforeNetwork(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--local-http"}, "requires non-empty --local-grants"},
		{[]string{"--local-http", "--local-grants={}"}, "requires non-empty --local-grants"},
		{[]string{"--local-grants={\"unknown\":[]}"}, "unknown or duplicate field"},
		{[]string{"--local-port=8080"}, "--local-port requires --local-http"},
		{[]string{"--stdio", "--local-http", `--local-grants={"tools":["*"]}`}, "--stdio cannot be combined"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			cmd, stderr := startupCommand(t, "offline", append([]string{"--tailnet=test", "--credential=test-only-token"}, tc.args...)...)
			if err := cmd.Run(); err == nil || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("configuration rejection: %v %s", err, stderr)
			}
		})
	}
}

type startupRPC func(string, any) map[string]json.RawMessage

// Exercise the configured SDK filter and handlers, not a hand-built probe tool.
// Return the exact number of permitted backend effects for either transport.
func startupProtocol(t *testing.T, request startupRPC, selectors []string) int64 {
	t.Helper()
	response := request("initialize", map[string]any{"protocolVersion": mcp.LATEST_PROTOCOL_VERSION, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "startup-test", "version": "1"}})
	if response["error"] != nil || !bytes.Contains(response["result"], []byte(`"serverInfo"`)) {
		t.Fatalf("initialize: %s", response)
	}
	response = request("tools/list", map[string]any{})
	var listed mcp.ListToolsResult
	if err := json.Unmarshal(response["result"], &listed); err != nil {
		t.Fatalf("list: %v %s", err, response)
	}
	_, catalog, err := newConfiguredMCPServer(nil, readapi.Client{}, true)
	if err != nil {
		t.Fatal(err)
	}
	visible := map[string]bool{}
	for _, tool := range listed.Tools {
		visible[tool.Name] = true
	}
	wantVisible := 0
	for _, tool := range catalog.Tools() {
		allowed := catalog.Allows(selectors, tool.Name)
		if allowed {
			wantVisible++
		}
		if visible[tool.Name] != allowed {
			t.Errorf("discovery mismatch for %s under %v", tool.Name, selectors)
		}
	}
	if len(visible) != len(listed.Tools) || len(visible) != wantVisible {
		t.Fatal("duplicate or unexpected tools in discovery")
	}
	var calls int64
	for _, name := range []string{"tailscale_get_dns_configuration", "tailscale_set_dns_configuration"} {
		response = request("tools/call", map[string]any{"name": name, "arguments": map[string]any{"body": map[string]any{}, "confirm": "setDnsConfiguration"}})
		if catalog.Allows(selectors, name) {
			var result mcp.CallToolResult
			if err := json.Unmarshal(response["result"], &result); err != nil || result.IsError {
				t.Fatalf("permitted call %s: %v %s", name, err, response)
			}
			calls++
		} else if response["error"] == nil {
			t.Fatalf("hidden tool accepted direct valid call: %s: %s", name, response)
		}
	}
	for _, tool := range []struct {
		name string
		args map[string]any
	}{
		{"tailscale_delete_device", map[string]any{"deviceId": "123", "confirm": "deleteDevice"}},
		{"tailscale_ping", map[string]any{"target": "test.example"}},
	} {
		if catalog.Allows(selectors, tool.name) {
			continue
		}
		response = request("tools/call", map[string]any{"name": tool.name, "arguments": tool.args})
		if response["error"] == nil {
			t.Fatalf("denied API/CLI tool accepted direct call: %s: %s", tool.name, response)
		}
	}
	response = request("resources/read", map[string]any{"uri": "tailscale://devices"})
	if response["error"] == nil {
		t.Fatalf("tool grant authorized resource: %s", response)
	}
	return calls
}

func TestStartupIntegrationConfiguredTransports(t *testing.T) {
	oldLogger := logger
	logger = zap.NewNop()
	t.Cleanup(func() { logger = oldLogger })
	cliDir := t.TempDir()
	marker := filepath.Join(cliDir, "called")
	if err := os.WriteFile(filepath.Join(cliDir, "tailscale"), []byte("#!/bin/sh\n: > \"$STARTUP_CLI_MARKER\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", cliDir)
	t.Setenv("STARTUP_CLI_MARKER", marker)
	for _, selectors := range [][]string{nil, {"tailscale_get_dns_configuration"}, {"*"}, {"read:*"}, {"group:dns"}, {"group:dns:read"}} {
		for _, transport := range []string{"stdio", "local", "peer"} {
			t.Run(transport+fmt.Sprint(selectors), func(t *testing.T) {
				caps := &MCPCapability{Tools: selectors}
				if transport == "stdio" {
					grant := map[string]any{}
					if selectors != nil {
						grant["tools"] = selectors
					}
					raw, _ := json.Marshal(grant)
					args := []string{"--stdio", "--local-cli", "--tailnet=test", `--credential={"type":"oauth","clientId":"test","clientSecret":"test-only-secret"}`, "--state=invalid://stdio-must-ignore"}
					if selectors != nil {
						args = append(args, "--local-grants="+string(raw))
					}
					cmd, stderr := startupCommand(t, "stdio", args...)
					cmd.Env = append(cmd.Env, "PATH="+cliDir, "STARTUP_CLI_MARKER="+marker)
					input, err := cmd.StdinPipe()
					if err != nil {
						t.Fatal(err)
					}
					output, err := cmd.StdoutPipe()
					if err != nil {
						t.Fatal(err)
					}
					if err := cmd.Start(); err != nil {
						t.Fatal(err)
					}
					enc, dec := json.NewEncoder(input), json.NewDecoder(output)
					want := startupProtocol(t, func(method string, params any) map[string]json.RawMessage {
						t.Helper()
						if err := enc.Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params}); err != nil {
							t.Fatal(err)
						}
						var response map[string]json.RawMessage
						if err := dec.Decode(&response); err != nil {
							t.Fatal(err)
						}
						return response
					}, selectors)
					_ = input.Close()
					if err := cmd.Wait(); err != nil {
						t.Fatalf("stdio main: %v %s", err, stderr)
					}
					if !strings.Contains(stderr.String(), fmt.Sprintf("startup API calls: %d\n", want)) {
						t.Fatalf("unexpected API effects: %s", stderr)
					}
					return
				}
				var calls atomic.Int64
				api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.URL.Path != "/tailnet/test/dns/configuration" {
						t.Errorf("unexpected backend request: %s", r.URL)
					}
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, `{}`)
				}))
				defer api.Close()
				baseURL, _ := url.Parse(api.URL)
				configured, _, err := newConfiguredMCPServer(&tsapi.Client{BaseURL: baseURL, HTTP: api.Client(), Tailnet: "test"}, readapi.Client{BaseURL: api.URL, HTTPClient: api.Client(), Tailnet: "test"}, true)
				if err != nil {
					t.Fatal(err)
				}
				sdk := server.NewStreamableHTTPServer(configured, server.WithEndpointPath(mcpEndpointPath))
				authorize := func(next http.Handler) http.Handler { return localGrantMiddleware(next, caps) }
				if transport == "peer" {
					authorize = func(next http.Handler) http.Handler {
						raw, _ := json.Marshal(caps)
						peer := peerGrantMiddleware(next, func(context.Context, string) (*apitype.WhoIsResponse, error) {
							return &apitype.WhoIsResponse{CapMap: tailcfg.PeerCapMap{mcpCapabilityKey: {tailcfg.RawMessage(raw)}}}, nil
						})
						return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							// Even a preexisting local grant must be replaced by peer identity.
							peer.ServeHTTP(w, r.WithContext(withCapabilities(r.Context(), &MCPCapability{Tools: []string{"*"}}, "local-http")))
						})
					}
				}
				httpServer := httptest.NewServer(mcpHTTPHandler(sdk, authorize))
				defer httpServer.Close()
				httpServer.Client().Timeout = 5 * time.Second
				var session string
				want := startupProtocol(t, func(method string, params any) map[string]json.RawMessage {
					t.Helper()
					raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
					req, _ := http.NewRequest("POST", httpServer.URL+mcpEndpointPath, bytes.NewReader(raw))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Accept", "application/json, text/event-stream")
					req.Header.Set("Mcp-Session-Id", session)
					req.Header.Set("X-Tailscale-Grants", `{"tools":["*"]}`)
					res, err := httpServer.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer res.Body.Close()
					if res.StatusCode != 200 {
						t.Fatalf("%s HTTP status=%d", method, res.StatusCode)
					}
					if method == "initialize" {
						session = res.Header.Get("Mcp-Session-Id")
					}
					var response map[string]json.RawMessage
					if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
						t.Fatal(err)
					}
					return response
				}, selectors)
				if calls.Load() != want {
					t.Fatalf("API effects=%d want=%d", calls.Load(), want)
				}
			})
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("denied tool invoked local CLI: %v", err)
	}
}

func TestStartupIntegrationTLSSelection(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("tls=%v/failure=%v", secure, fail), func(t *testing.T) {
				failure := errors.New("certificate or listener unavailable")
				var calls int
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				selected := func(network, addr string) (net.Listener, error) {
					calls++
					if network != "tcp" || addr != ":8443" {
						t.Fatalf("listen(%q,%q)", network, addr)
					}
					if fail {
						return nil, failure
					}
					return listener, nil
				}
				status := &ipnstate.Status{CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSEnabled: true}, CertDomains: []string{"mcp.example.ts.net"}}
				got, err := listenTailnet(selected, status, 8443, secure, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, failure })
				if calls != 1 || (fail && (!errors.Is(err, failure) || got != nil)) || (!fail && (err != nil || got == nil || (!secure && got != listener))) {
					t.Fatalf("listener=%v error=%v calls=%d", got, err, calls)
				}
			})
		}
	}
	for _, tc := range []struct {
		host string
		port int
		tls  bool
		want string
	}{
		{"mcp.example.ts.net", 443, true, "https://mcp.example.ts.net:443/mcp"},
		{"mcp.example.ts.net", 8443, true, "https://mcp.example.ts.net:8443/mcp"},
		{"mcp.example.ts.net", 8080, false, "http://mcp.example.ts.net:8080/mcp"},
		{"127.0.0.1", 9090, false, "http://127.0.0.1:9090/mcp"},
		{"::1", 8080, false, "http://[::1]:8080/mcp"},
	} {
		if got := endpointURL(tc.host, tc.port, tc.tls); got != tc.want {
			t.Errorf("endpoint=%q want=%q", got, tc.want)
		}
	}
}

func TestStartupIntegrationTLSScheme(t *testing.T) {
	oldLogger := logger
	logger = zap.NewNop()
	defer func() { logger = oldLogger }()
	configured, _, err := newConfiguredMCPServer(nil, readapi.Client{}, false)
	if err != nil {
		t.Fatal(err)
	}
	handler := mcpHTTPHandler(server.NewStreamableHTTPServer(configured), func(next http.Handler) http.Handler { return localGrantMiddleware(next, nil) })
	for _, secure := range []bool{false, true} {
		s := httptest.NewUnstartedServer(handler)
		if secure {
			s.StartTLS()
		} else {
			s.Start()
		}
		t.Cleanup(s.Close)
		s.Client().Timeout = 5 * time.Second
		for _, matching := range []bool{false, true} {
			origin := s.URL
			forwarded := "http"
			if !secure {
				forwarded = "https"
			}
			if !matching {
				origin = forwarded + "://" + strings.SplitN(s.URL, "://", 2)[1]
			}
			req, _ := http.NewRequest("POST", s.URL+mcpEndpointPath, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"tls-test","version":"1"}}}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("Origin", origin)
			req.Header.Set("X-Forwarded-Proto", forwarded)
			req.Header.Set("Forwarded", "proto="+forwarded)
			res, err := s.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			want := http.StatusForbidden
			if matching {
				want = http.StatusOK
			}
			if res.StatusCode != want || (matching && !bytes.Contains(body, []byte(`"serverInfo"`))) {
				t.Fatalf("TLS=%v matching=%v: %d %s", secure, matching, res.StatusCode, body)
			}
			if secure && (res.TLS == nil || res.TLS.Version < tls.VersionTLS12) {
				t.Fatal("no real TLS handshake")
			}
		}
		s.Close()
	}
}

func TestStartupIntegrationSignals(t *testing.T) {
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			cmd, stderr := startupCommand(t, "signals")
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			var addresses []string
			if err := json.NewDecoder(stdout).Decode(&addresses); err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Timeout: 5 * time.Second}
			stream, err := client.Get("http://" + addresses[0] + "/stream")
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Body.Close()
			local, err := client.Get("http://" + addresses[1] + "/local")
			if err != nil {
				t.Fatal(err)
			}
			local.Body.Close()
			if local.StatusCode != 204 {
				t.Fatalf("local status=%d", local.StatusCode)
			}
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("signal shutdown: %v %s", err, stderr)
			}
			if _, err := io.ReadAll(stream.Body); err != nil {
				t.Fatalf("stream did not drain normally: %v", err)
			}
			for _, addr := range addresses {
				conn, err := net.DialTimeout("tcp", addr, time.Second)
				if err == nil {
					conn.Close()
					t.Fatalf("listener survived process exit: %s", addr)
				}
			}
		})
	}
	cmd, stderr := startupCommand(t, "serve-failure")
	if err := cmd.Run(); err == nil || !strings.Contains(stderr.String(), "startup injected accept failure") {
		t.Fatalf("unexpected serving failure exit: %v %s", err, stderr)
	}
}

func TestStartupIntegrationStdioCancellationWithOpenInput(t *testing.T) {
	for _, cause := range []string{"context", "interrupt", "terminate"} {
		t.Run(cause, func(t *testing.T) {
			mode := "stdio"
			if cause == "context" {
				mode = "stdio-context"
			}
			cmd, stderr := startupCommand(t, mode, "--stdio", "--tailnet=test", "--credential=test-only-token", `--local-grants={"tools":["read:*"]}`)
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintln(input, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"shutdown-test","version":"1"}}}`); err != nil {
				t.Fatal(err)
			}
			var response map[string]json.RawMessage
			if err := json.NewDecoder(output).Decode(&response); err != nil || response["result"] == nil {
				t.Fatalf("initialize: %v %s", err, response)
			}
			if cause == "context" {
				// The fake API cancels run's context, without delivering a signal.
				_, err = fmt.Fprintln(input, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tailscale_get_dns_configuration","arguments":{}}}`)
			} else {
				sig := os.Interrupt
				if cause == "terminate" {
					sig = syscall.SIGTERM
				}
				err = cmd.Process.Signal(sig)
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("stdio shutdown: %v %s", err, stderr)
				}
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				t.Fatalf("stdio shutdown hung with stdin open: %s", stderr)
			}
		})
	}
}
