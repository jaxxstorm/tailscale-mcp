package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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

	"github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
)

type testTailnetServer struct {
	start  func() error
	up     func(context.Context) (*ipnstate.Status, error)
	listen func(string, string) (net.Listener, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	client func() (*local.Client, error)
	close  func() error
}

func (s testTailnetServer) Start() error                                     { return s.start() }
func (s testTailnetServer) Up(ctx context.Context) (*ipnstate.Status, error) { return s.up(ctx) }
func (s testTailnetServer) Listen(network, addr string) (net.Listener, error) {
	return s.listen(network, addr)
}
func (s testTailnetServer) LocalClient() (*local.Client, error) { return s.client() }
func (s testTailnetServer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.dial(ctx, network, addr)
}
func (s testTailnetServer) Close() error { return s.close() }

func readyTailnetStatus() *ipnstate.Status {
	return &ipnstate.Status{
		Self:           &ipnstate.PeerStatus{DNSName: "mcp.example.ts.net."},
		TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")},
		CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSEnabled: true},
		CertDomains:    []string{"mcp.example.ts.net"},
	}
}

func TestTailnetReadinessCancellationBeforeBinding(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint("tls=", secure), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			waiting := make(chan struct{})
			var starts, closes, ups atomic.Int32
			ts := testTailnetServer{
				start: func() error { starts.Add(1); return nil },
				up: func(ctx context.Context) (*ipnstate.Status, error) {
					ups.Add(1)
					close(waiting)
					<-ctx.Done()
					return nil, ctx.Err()
				},
				close: func() error { closes.Add(1); return nil },
				// Unexpected LocalClient/Listen calls panic rather than touching a network.
			}
			done := make(chan error, 1)
			go func() {
				done <- serveMCPHTTP(ctx, ts, nil, CLI{Tailscale: true, ApertureURL: "http://ai/aperture", TLS: secure, LocalHTTP: true}, 443, 8080, &MCPCapability{Tools: []string{"*"}})
			}()
			<-waiting
			cancel()
			select {
			case err := <-done:
				if !expectedCancellation(ctx, err) {
					t.Fatalf("readiness cancellation = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("readiness did not honor cancellation")
			}
			if starts.Load() != 1 || ups.Load() != 1 || closes.Load() != 1 {
				t.Fatalf("start/up/close=%d/%d/%d", starts.Load(), ups.Load(), closes.Load())
			}
		})
	}
}

func TestTailnetInitializationNeverRacesClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	starting, release := make(chan struct{}), make(chan struct{})
	var closes atomic.Int32
	ts := testTailnetServer{
		start: func() error { close(starting); <-release; return nil },
		close: func() error { closes.Add(1); return nil },
	}
	done := make(chan error, 1)
	go func() {
		done <- serveMCPHTTP(ctx, ts, nil, CLI{Tailscale: true, ApertureURL: "http://ai/aperture"}, 8080, 8080, nil)
	}()
	<-starting
	cancel()
	select {
	case err := <-done:
		t.Fatalf("returned while Start was still running: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if closes.Load() != 0 {
		t.Fatal("Close raced initialization")
	}
	close(release)
	if err := <-done; !expectedCancellation(ctx, err) {
		t.Fatal(err)
	}
	if closes.Load() != 1 {
		t.Fatal("successful initialization was not cleaned up")
	}
	// This SDK failure occurs before s.sys exists. Calling Close after it would
	// panic; Start's own close-on-error pool is the appropriate cleanup path.
	err := serveMCPHTTP(context.Background(), &tsnet.Server{Store: new(mem.Store)}, nil, CLI{Tailscale: true, ApertureURL: "http://ai/aperture"}, 8080, 8080, nil)
	if err == nil || !strings.Contains(err.Error(), "in-memory store") {
		t.Fatalf("SDK initialization error = %v", err)
	}
}

func TestTailnetStartupErrorPreservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	failure := errors.New("independent listener failure")
	for _, err := range []error{failure, errors.Join(context.Canceled, failure), context.DeadlineExceeded} {
		if expectedCancellation(ctx, err) {
			t.Fatalf("suppressed failure %v", err)
		}
	}
	if !expectedCancellation(ctx, fmt.Errorf("readiness: %w", context.Canceled)) {
		t.Fatal("expected cancellation was not recognized")
	}
	if expectedCancellation(context.Background(), context.Canceled) {
		t.Fatal("unrelated cancellation suppressed")
	}
	ctx, cancel = context.WithCancel(context.Background())
	ts := testTailnetServer{
		start: func() error { return nil },
		up:    func(context.Context) (*ipnstate.Status, error) { cancel(); return nil, context.Canceled },
		close: func() error { return failure },
	}
	err := serveMCPHTTP(ctx, ts, nil, CLI{Tailscale: true, ApertureURL: "http://ai/aperture"}, 8080, 8080, nil)
	if !errors.Is(err, failure) || expectedCancellation(ctx, err) {
		t.Fatalf("cleanup failure hidden: %v", err)
	}
}

func TestRunExpectedStartupCancellation(t *testing.T) {
	oldLogger, oldTransport := logger, http.DefaultTransport
	logger = zap.NewNop()
	defer func() { logger, http.DefaultTransport = oldLogger, oldTransport }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	http.DefaultTransport = credentialRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, r.Context().Err()
	})
	if err := run(ctx, CLI{Tailscale: true, ApertureURL: "invalid://unused", Tailnet: "test", Credential: "test-only-token"}); err != nil {
		t.Fatalf("expected cancellation returned failure: %v", err)
	}
	if err := run(ctx, CLI{Tailscale: true, ApertureURL: "http://ai/aperture", Tailnet: "test", Credential: "{"}); err == nil {
		t.Fatal("signal suppressed invalid configuration")
	}
}

func TestRunApertureOnlySkipsAdminAPI(t *testing.T) {
	oldLogger, oldTransport := logger, http.DefaultTransport
	logger = zap.NewNop()
	defer func() { logger, http.DefaultTransport = oldLogger, oldTransport }()
	http.DefaultTransport = credentialRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("Aperture-only startup contacted the Admin API")
		return nil, errors.New("unexpected Admin API request")
	})
	for _, tc := range []struct {
		name, credential, tags, want string
		canceled                     bool
	}{
		{name: "enrollment credential required", want: "TAILSCALE_OAUTH_TOKEN"},
		{name: "invalid enrollment credential", credential: "{", want: "TAILSCALE_OAUTH_TOKEN"},
		{name: "OAuth enrollment tags required", credential: `{"type":"oauth","clientId":"test","clientSecret":"test-only-secret"}`, want: "TS_ADVERTISE_TAGS"},
		{name: "bearer reaches state validation", credential: "test-only-token", want: "unsupported TSNET_STATE"},
		{name: "OAuth reaches state validation", credential: `{"type":"oauth","clientId":"test","clientSecret":"test-only-secret"}`, tags: "tag:mcp-server", want: "unsupported TSNET_STATE"},
		{name: "cancellation before tsnet", credential: "test-only-token", canceled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			err := run(ctx, CLI{Aperture: true, ApertureURL: "http://ai/aperture", Credential: tc.credential, AdvertiseTags: tc.tags, State: "invalid://must-not-initialize"})
			if tc.canceled {
				if err != nil {
					t.Fatalf("expected cancellation: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("startup error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestMCPListenerAcquisitionOptInAndCancellation(t *testing.T) {
	for _, scenario := range []string{"disabled", "enabled", "local failure", "cancel tailnet bind", "cancel local bind", "already canceled"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "already canceled" {
				cancel()
			}
			var acquired []net.Listener
			var tailCalls, localCalls int
			bind := func() (net.Listener, error) {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err == nil {
					acquired = append(acquired, l)
					t.Cleanup(func() { l.Close() })
				}
				return l, err
			}
			failure := errors.New("loopback bind failed")
			listeners, err := acquireMCPListeners(ctx, func() (net.Listener, error) {
				tailCalls++
				l, err := bind()
				if scenario == "cancel tailnet bind" {
					cancel()
				}
				return l, err
			}, scenario != "disabled", 9090, func(network, addr string) (net.Listener, error) {
				localCalls++
				if network != "tcp" || addr != "127.0.0.1:9090" {
					t.Fatalf("local bind=%q %q", network, addr)
				}
				if scenario == "local failure" {
					return nil, failure
				}
				l, err := bind()
				if scenario == "cancel local bind" {
					cancel()
				}
				return l, err
			})
			if scenario == "disabled" || scenario == "enabled" {
				want := 1
				if scenario == "enabled" {
					want = 2
				}
				if err != nil || len(listeners) != want || localCalls != want-1 {
					t.Fatalf("listeners=%d local calls=%d err=%v", len(listeners), localCalls, err)
				}
				return
			}
			if err == nil || listeners != nil {
				t.Fatalf("failure accepted: %v", err)
			}
			if scenario == "local failure" && !errors.Is(err, failure) {
				t.Fatal(err)
			}
			if scenario != "local failure" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if scenario == "already canceled" && tailCalls != 0 {
				t.Fatal("bound after cancellation")
			}
			if scenario == "cancel tailnet bind" && localCalls != 0 {
				t.Fatal("local bind after cancellation")
			}
			for _, l := range acquired {
				if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("partial listener remains: %v", err)
				}
			}
		})
	}
}

type tailnetRemoteListener struct{ net.Listener }
type tailnetRemoteConn struct{ net.Conn }

func (l tailnetRemoteListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return tailnetRemoteConn{c}, nil
}
func (c tailnetRemoteConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("100.64.0.2"), Port: 12345}
}
func (c tailnetRemoteConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: 8080}
}

func TestTailnetCanonicalHostProductionStack(t *testing.T) {
	oldLogger := logger
	logger = zap.NewNop()
	defer func() { logger = oldLogger }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var whoCalls, dialCalls atomic.Int32
	var unavailable atomic.Bool
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:1234")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:1234")
	lc := &local.Client{OmitAuth: true, Transport: credentialRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		whoCalls.Add(1)
		if r.URL.Path != "/localapi/v0/whois" || r.URL.Query().Get("addr") != "100.64.0.2:12345" {
			t.Errorf("unexpected WhoIs request: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"UserProfile":{"LoginName":"trusted-peer"},"CapMap":{"jaxxstorm.com/cap/mcp":[{"tools":["*"]}]}}`))}, nil
	})}
	ts := testTailnetServer{
		start:  func() error { return nil },
		up:     func(context.Context) (*ipnstate.Status, error) { return readyTailnetStatus(), nil },
		client: func() (*local.Client, error) { return lc, nil },
		listen: func(string, string) (net.Listener, error) { return tailnetRemoteListener{l}, nil },
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCalls.Add(1)
			if network != "tcp" || addr != "ai:80" {
				t.Errorf("Aperture dial=%q %q", network, addr)
			}
			if unavailable.Load() {
				return nil, errors.New("Aperture unavailable")
			}
			client, backend := net.Pipe()
			go func() {
				defer backend.Close()
				_ = backend.SetDeadline(time.Now().Add(3 * time.Second))
				req, err := http.ReadRequest(bufio.NewReader(backend))
				if err != nil {
					t.Error(err)
					return
				}
				defer req.Body.Close()
				if req.Method != http.MethodGet || req.URL.Path != "/custom/aperture/pricing" {
					t.Errorf("upstream request=%s %s", req.Method, req.URL)
				}
				for _, header := range []string{"Authorization", "Cookie", "X-Tailscale-User"} {
					if req.Header.Get(header) != "" {
						t.Errorf("forwarded %s", header)
					}
				}
				body := `{"currency":"USD","cost_bases":["retail"],"units":{},"models":{},"configured_adjustments":{"providers":{}}}`
				fmt.Fprintf(backend, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"pricing-version\"\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
			}()
			return client, nil
		},
		close: func() error { return nil },
	}
	done := make(chan error, 1)
	go func() {
		done <- serveMCPHTTP(ctx, ts, server.NewMCPServer("host-test", "test"), CLI{Tailscale: true, Aperture: true, ApertureURL: "http://ai/custom/aperture/", Hostname: "untrusted-cli-alias"}, 8080, 9090, nil)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client := &http.Client{Timeout: 3 * time.Second}
	sessions := make(map[string]string)
	for _, host := range []string{"attacker.example:8080", "untrusted-cli-alias:8080", "mcp.example.ts.net.evil:8080", "mcp.example.ts.net:9090", "mcp.example.ts.net", "localhost:8080", "mcp.example.ts.net:8080", "MCP:8080", "100.64.0.1:8080", "[fd7a:115c:a1e0::1]:8080"} {
		for _, path := range []string{mcpEndpointPath, apertureEndpointPath} {
			for _, withOrigin := range []bool{false, true} {
				req, _ := http.NewRequest("POST", "http://"+l.Addr().String()+path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"host-test","version":"1"}}}`))
				req.Host = host
				if withOrigin {
					req.Header.Set("Origin", "http://"+host)
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "application/json, text/event-stream")
				req.Header.Set("Forwarded", "host=mcp.example.ts.net:8080;proto=http")
				req.Header.Set("X-Forwarded-Host", "mcp.example.ts.net:8080")
				before := whoCalls.Load()
				res, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(res.Body)
				res.Body.Close()
				allowed := host == "mcp.example.ts.net:8080" || host == "MCP:8080" || host == "100.64.0.1:8080" || host == "[fd7a:115c:a1e0::1]:8080"
				if allowed {
					sessions[path] = res.Header.Get("Mcp-Session-Id")
					if res.StatusCode != 200 || !strings.Contains(string(body), "serverInfo") || whoCalls.Load() != before+1 {
						t.Fatalf("canonical host %s origin=%v: %d %s", host, withOrigin, res.StatusCode, body)
					}
				} else if res.StatusCode != 403 || whoCalls.Load() != before {
					t.Fatalf("untrusted host %s origin=%v: %d %s", host, withOrigin, res.StatusCode, body)
				}
			}
		}
	}
	if dialCalls.Load() != 0 {
		t.Fatal("startup or initialization probed Aperture availability")
	}
	for _, fail := range []bool{false, true} {
		unavailable.Store(fail)
		req, _ := http.NewRequest("POST", "http://"+l.Addr().String()+apertureEndpointPath, strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"aperture_get_pricing","arguments":{}}}`))
		req.Host = "mcp.example.ts.net:8080"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Mcp-Session-Id", sessions[apertureEndpointPath])
		req.Header.Set("Authorization", "Bearer caller-secret")
		req.Header.Set("Cookie", "caller=secret")
		req.Header.Set("X-Tailscale-User", "spoofed")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var response struct {
			Result struct {
				IsError bool            `json:"isError"`
				Content json.RawMessage `json:"content"`
			} `json:"result"`
			Error json.RawMessage `json:"error"`
		}
		err = json.NewDecoder(res.Body).Decode(&response)
		res.Body.Close()
		if err != nil || res.StatusCode != 200 || response.Error != nil || response.Result.IsError != fail {
			t.Fatalf("Aperture unavailable=%v: status=%d response=%+v err=%v", fail, res.StatusCode, response, err)
		}
	}
	if dialCalls.Load() != 2 {
		t.Fatalf("tsnet dial calls=%d want=2", dialCalls.Load())
	}
	sessions[legacyMCPEndpointPath] = sessions[mcpEndpointPath]
	for _, path := range []string{mcpEndpointPath, apertureEndpointPath, legacyMCPEndpointPath} {
		req, _ := http.NewRequest("POST", "http://"+l.Addr().String()+path, strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`))
		req.Host = "mcp.example.ts.net:8080"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Mcp-Session-Id", sessions[path])
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		want := http.StatusOK
		if res.StatusCode != want || res.Header.Get("Location") != "" {
			t.Fatalf("route %s after upstream failure: status=%d", path, res.StatusCode)
		}
	}
}

func TestTailnetApertureDisabledProductionStack(t *testing.T) {
	oldLogger, oldTransport := logger, http.DefaultTransport
	logger = zap.NewNop()
	defer func() { logger, http.DefaultTransport = oldLogger, oldTransport }()
	// Disabled startup must not clone the default transport to build an Aperture client.
	http.DefaultTransport = credentialRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("disabled Aperture used the default HTTP transport")
		return nil, errors.New("unexpected HTTP request")
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	lc := &local.Client{OmitAuth: true, Transport: credentialRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"CapMap":{"jaxxstorm.com/cap/mcp":[{"tools":["*"]}]}}`))}, nil
	})}
	var dialCalls atomic.Int32
	ts := testTailnetServer{
		start:  func() error { return nil },
		up:     func(context.Context) (*ipnstate.Status, error) { return readyTailnetStatus(), nil },
		client: func() (*local.Client, error) { return lc, nil },
		listen: func(string, string) (net.Listener, error) { return tailnetRemoteListener{l}, nil },
		dial: func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("disabled Aperture dial")
		},
		close: func() error { return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveMCPHTTP(ctx, ts, server.NewMCPServer("disabled-test", "test"), CLI{Tailscale: true, ApertureURL: "invalid://unused"}, 8080, 9090, nil)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for _, path := range []string{apertureEndpointPath, mcpEndpointPath, legacyMCPEndpointPath} {
		req, _ := http.NewRequest("POST", "http://"+l.Addr().String()+path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"disabled-test","version":"1"}}}`))
		req.Host = "mcp.example.ts.net:8080"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		want := http.StatusOK
		if path == apertureEndpointPath {
			want = http.StatusNotFound
		}
		if res.StatusCode != want || (want == http.StatusOK && !strings.Contains(string(body), "serverInfo")) {
			t.Fatalf("route %s: status=%d body=%s", path, res.StatusCode, body)
		}
	}
	if dialCalls.Load() != 0 {
		t.Fatalf("disabled Aperture dial calls=%d", dialCalls.Load())
	}
}

func TestTailnetTailscaleDisabledProductionStack(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	oldLogger := logger
	logger = zap.New(core)
	defer func() { logger = oldLogger }()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	lc := &local.Client{OmitAuth: true, Transport: credentialRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"CapMap":{"jaxxstorm.com/cap/mcp":[{"tools":["*"]}]}}`))}, nil
	})}
	ts := testTailnetServer{
		start:  func() error { return nil },
		up:     func(context.Context) (*ipnstate.Status, error) { return readyTailnetStatus(), nil },
		client: func() (*local.Client, error) { return lc, nil },
		listen: func(string, string) (net.Listener, error) { return tailnetRemoteListener{l}, nil },
		dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("startup or discovery contacted Aperture backend")
			return nil, errors.New("unexpected backend dial")
		},
		close: func() error { return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		// A nil server catches unconditional Tailscale streamable construction.
		done <- serveMCPHTTP(ctx, ts, nil, CLI{Aperture: true, ApertureURL: "http://ai/aperture", LocalHTTP: true}, 8080, 0, &MCPCapability{Tools: []string{"*"}})
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client := &http.Client{Timeout: 3 * time.Second}
	for _, path := range []string{mcpEndpointPath, legacyMCPEndpointPath, apertureEndpointPath} {
		req, _ := http.NewRequest("POST", "http://"+l.Addr().String()+path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"aperture-only","version":"1"}}}`))
		req.Host = "mcp.example.ts.net:8080"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		want := http.StatusNotFound
		if path == apertureEndpointPath {
			want = http.StatusOK
		}
		if res.StatusCode != want || (want == http.StatusOK && !strings.Contains(string(body), "serverInfo")) {
			t.Fatalf("route %s: status=%d body=%s", path, res.StatusCode, body)
		}
	}
	var apertureURLs int
	for _, entry := range logs.All() {
		if raw, ok := entry.ContextMap()["url"].(string); ok {
			endpoint, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if endpoint.Path == mcpEndpointPath || endpoint.Path == legacyMCPEndpointPath {
				t.Errorf("disabled Tailscale URL advertised: %s", raw)
			}
			if strings.HasSuffix(raw, apertureEndpointPath) {
				apertureURLs++
			}
		}
	}
	if apertureURLs != 2 {
		t.Fatalf("Aperture listener URLs=%d, want 2", apertureURLs)
	}
}

func TestCanceledBeforeHTTPServeClosesAcquiredListeners(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var bindings []httpServerListener
	for range 2 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		bindings = append(bindings, httpServerListener{newHTTPServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("served after cancellation") })), l})
	}
	if err := serveHTTPServers(ctx, 0, bindings...); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled startup: %v", err)
	}
	for _, binding := range bindings {
		if _, err := binding.Listener.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("listener left open: %v", err)
		}
	}
}

func TestTailnetTLSPrerequisitesAndHandshakes(t *testing.T) {
	for _, scenario := range []string{"nil status", "no tailnet", "no MagicDNS", "no certificates", "no provider"} {
		t.Run(scenario, func(t *testing.T) {
			status := readyTailnetStatus()
			provider := func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				t.Fatal("unexpected certificate lookup")
				return nil, nil
			}
			switch scenario {
			case "nil status":
				status = nil
			case "no tailnet":
				status.CurrentTailnet = nil
			case "no MagicDNS":
				status.CurrentTailnet.MagicDNSEnabled = false
			case "no certificates":
				status.CertDomains = nil
			case "no provider":
				provider = nil
			}
			_, err := listenTailnet(func(string, string) (net.Listener, error) {
				t.Fatal("bound despite missing TLS prerequisite")
				return nil, nil
			}, status, 443, true, provider)
			if err == nil {
				t.Fatal("missing TLS prerequisite accepted")
			}
		})
	}
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	for _, failCertificate := range []bool{false, true} {
		t.Run(fmt.Sprint("certificate failure=", failCertificate), func(t *testing.T) {
			var certCalls atomic.Int32
			l, err := listenTailnet(func(string, string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }, readyTailnetStatus(), 443, true, func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				certCalls.Add(1)
				if hello.ServerName != "mcp.example.ts.net" {
					t.Errorf("SNI=%q", hello.ServerName)
				}
				if failCertificate {
					return nil, errors.New("certificate issuance failed")
				}
				return &certificate, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			s := newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
			defer s.Close()
			go s.Serve(l)
			transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "mcp.example.ts.net", InsecureSkipVerify: true}} // Test-only certificate.
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			res, err := client.Get("https://" + l.Addr().String())
			if failCertificate {
				if err == nil {
					res.Body.Close()
					t.Fatal("failed issuance accepted")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				if res.StatusCode != 204 || res.TLS == nil {
					t.Fatal("TLS did not complete")
				}
			}
			if certCalls.Load() != 1 {
				t.Fatalf("certificate lookups=%d", certCalls.Load())
			}
			res, err = client.Get("http://" + l.Addr().String())
			if err == nil {
				res.Body.Close()
				if res.StatusCode == 204 {
					t.Fatal("TLS fell back to plaintext")
				}
			}
		})
	}
}
