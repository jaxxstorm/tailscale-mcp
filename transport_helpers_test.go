package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestResolveTransportPorts(t *testing.T) {
	p := func(n int) *int { return &n }
	for _, tc := range []struct {
		name                string
		port, local         *int
		tls, http, stdio    bool
		wantTail, wantLocal int
		fail                bool
	}{
		{name: "defaults", wantTail: 8080, wantLocal: 8080},
		{name: "TLS independent local", tls: true, http: true, wantTail: 443, wantLocal: 8080},
		{name: "explicit", port: p(8443), local: p(9090), tls: true, http: true, wantTail: 8443, wantLocal: 9090},
		{name: "explicit zero", port: p(0), fail: true},
		{name: "negative", local: p(-1), http: true, fail: true},
		{name: "too large", port: p(65536), fail: true},
		{name: "local opt in required", local: p(8080), fail: true},
		{name: "stdio local conflict", http: true, stdio: true, fail: true},
		{name: "stdio tls conflict", tls: true, stdio: true, fail: true},
		{name: "stdio explicit port conflict", port: p(8080), stdio: true, fail: true},
		{name: "stdio", stdio: true, wantTail: 8080, wantLocal: 8080},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b, err := resolvePorts(tc.port, tc.local, tc.tls, tc.http, tc.stdio)
			if (err != nil) != tc.fail || (!tc.fail && (a != tc.wantTail || b != tc.wantLocal)) {
				t.Fatalf("got (%d, %d, %v)", a, b, err)
			}
		})
	}
}

func TestStrictOriginTuples(t *testing.T) {
	for _, tc := range []struct {
		origin, host string
		tls, allowed bool
	}{
		{"", "example.com", false, true},
		{"http://EXAMPLE.com:80", "example.com", false, true},
		{"https://example.com", "EXAMPLE.COM:443", true, true},
		{"http://[::1]:8080", "[::1]:8080", false, true},
		{"http://example.com.evil", "example.com", false, false},
		{"https://example.com", "example.com", false, false},
		{"http://example.com:8080", "example.com", false, false},
		{"http://example.com/", "example.com", false, false},
		{"http://example.com?", "example.com", false, false},
		{"http://example.com#", "example.com", false, false},
		{"http://user@example.com", "example.com", false, false},
		{"null", "example.com", false, false},
		{"http://example.com http://evil", "example.com", false, false},
		{"http://example.com,http://evil", "example.com", false, false},
		{"http://example.com:", "example.com", false, false},
		{"http://example.com:0", "example.com", false, false},
		{"http://example.com:65536", "example.com", false, false},
		{"http://example.com/path", "example.com", false, false},
		{"http://[example.com]", "example.com", false, false},
	} {
		t.Run(tc.origin+tc.host, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://"+tc.host+"/mcp", nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			r.Header.Set("Forwarded", "host=evil;proto=https")
			r.Header.Set("X-Forwarded-Host", "evil")
			r.Header.Set("X-Forwarded-Proto", "https")
			if got := originAllowed(r); got != tc.allowed {
				t.Fatalf("allowed = %v", got)
			}
		})
	}
	r := httptest.NewRequest("POST", "http://example.com/mcp", nil)
	r.Header["Origin"] = []string{"http://example.com", "http://example.com"}
	if originAllowed(r) {
		t.Fatal("multiple headers accepted")
	}
	r.Header["Origin"] = []string{""}
	if originAllowed(r) {
		t.Fatal("empty present origin accepted")
	}
}

func TestHTTPBounds(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(bodyLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(w, r.Body)
	}), 0))
	defer s.Close()
	for _, chunked := range []bool{false, true} {
		req, _ := http.NewRequest("POST", s.URL, strings.NewReader(strings.Repeat("x", int(maxMCPBodyBytes)+1)))
		if chunked {
			req.ContentLength = -1
		}
		res, err := s.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("chunked=%v: %d", chunked, res.StatusCode)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("oversized body dispatched")
	}
	// Representative large ACL text, well below the request bound.
	payload := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"update_acl","arguments":{"policy":"` + strings.Repeat("allow;", 100000) + `"}}}`
	res, err := s.Client().Post(s.URL, "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || string(body) != payload || calls.Load() != 1 {
		t.Fatalf("valid ACL body failed: %v", err)
	}
	configured := newHTTPServer(http.NotFoundHandler())
	if configured.ReadHeaderTimeout != 10*time.Second || configured.IdleTimeout != 120*time.Second || configured.WriteTimeout != 0 || configured.ReadTimeout != 0 {
		t.Fatalf("unexpected server limits: %+v", configured)
	}
}

func TestBodyDeadlineSlowReadAndStreamSurvival(t *testing.T) {
	const deadline = 50 * time.Millisecond
	var calls atomic.Int32
	s := httptest.NewServer(bodyLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: start\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(4 * deadline)
		if r.Context().Err() != nil {
			return
		}
		fmt.Fprint(w, "data: survived\n\n")
	}), deadline))
	defer s.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(s.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(conn, "POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx")
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusRequestTimeout || calls.Load() != 0 {
		t.Fatalf("slow body: status=%d calls=%d", res.StatusCode, calls.Load())
	}
	res, err = s.Client().Post(s.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || !strings.Contains(string(body), "survived") {
		t.Fatalf("stream truncated: %q %v", body, err)
	}
}

func TestAcquireListenersClosesOnSecondFailure(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("local bind failed")
	_, err = acquireListeners(func() (net.Listener, error) { return first, nil }, func() (net.Listener, error) { return nil, failure })
	if !errors.Is(err, failure) {
		t.Fatalf("lost bind failure: %v", err)
	}
	if _, err := first.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("first listener not closed: %v", err)
	}
}

func TestCoordinatedHTTPShutdown(t *testing.T) {
	for _, stubborn := range []bool{false, true} {
		t.Run(fmt.Sprint("stubborn=", stubborn), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			release := make(chan struct{})
			defer close(release)
			started := make(chan struct{})
			listeners, err := acquireListeners(func() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }, func() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") })
			if err != nil {
				t.Fatal(err)
			}
			stream := newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "data: open\n\n")
				w.(http.Flusher).Flush()
				close(started)
				if stubborn {
					<-release
				} else {
					<-r.Context().Done()
				}
			}))
			local := newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
			done := make(chan error, 1)
			go func() {
				done <- serveHTTPServers(ctx, 100*time.Millisecond, httpServerListener{stream, listeners[0]}, httpServerListener{local, listeners[1]})
			}()
			client := &http.Client{Timeout: 3 * time.Second}
			res, err := client.Get("http://" + listeners[0].Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			<-started
			localRes, err := client.Get("http://" + listeners[1].Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			localRes.Body.Close()
			cancel()
			// Local acceptance must stop even while a stubborn stream is draining.
			until := time.Now().Add(80 * time.Millisecond)
			for {
				conn, err := net.DialTimeout("tcp", listeners[1].Addr().String(), 10*time.Millisecond)
				if err != nil {
					break
				}
				conn.Close()
				if time.Now().After(until) {
					t.Fatal("local listener still accepting during drain")
				}
				time.Sleep(time.Millisecond)
			}
			select {
			case err := <-done:
				if stubborn && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("missing drain timeout: %v", err)
				}
				if !stubborn && err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("shutdown hung")
			}
			if stubborn {
				if _, err := io.ReadAll(res.Body); err == nil {
					t.Fatal("stubborn stream was not force closed")
				}
			}
		})
	}
}

type failedTransportListener struct {
	net.Listener
	failure error
}

func (l failedTransportListener) Accept() (net.Conn, error) { return nil, l.failure }

func TestUnexpectedServeFailureIsReturned(t *testing.T) {
	listeners, err := acquireListeners(func() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }, func() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") })
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("unexpected accept failure")
	err = serveHTTPServers(context.Background(), time.Second,
		httpServerListener{newHTTPServer(http.NotFoundHandler()), failedTransportListener{listeners[0], failure}},
		httpServerListener{newHTTPServer(http.NotFoundHandler()), listeners[1]})
	if !errors.Is(err, failure) {
		t.Fatalf("lost serving failure: %v", err)
	}
	for _, l := range listeners {
		if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("listener not closed: %v", err)
		}
	}
}
