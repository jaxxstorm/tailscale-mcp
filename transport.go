package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
)

const (
	maxMCPBodyBytes    int64 = 4 << 20
	mcpBodyReadTimeout       = 30 * time.Second
	mcpShutdownTimeout       = 10 * time.Second
)

type tailnetServer interface {
	Start() error
	Up(context.Context) (*ipnstate.Status, error)
	Listen(network, addr string) (net.Listener, error)
	LocalClient() (*local.Client, error)
	Close() error
}

// Unlike tsnet.ListenTLS, this does not repeat Up with a background context.
// The caller must have completed Start and Up(ctx) before binding.
func listenTailnet(listen func(string, string) (net.Listener, error), status *ipnstate.Status, port int, secure bool, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) (net.Listener, error) {
	if secure {
		if status == nil || status.CurrentTailnet == nil || !status.CurrentTailnet.MagicDNSEnabled {
			return nil, errors.New("tailnet TLS requires MagicDNS; see https://tailscale.com/s/https")
		}
		if len(status.CertDomains) == 0 {
			return nil, errors.New("tailnet TLS requires HTTPS certificates enabled; see https://tailscale.com/s/https")
		}
		if getCertificate == nil {
			return nil, errors.New("tailnet TLS requires a certificate provider")
		}
	}
	listener, err := listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	if secure {
		return tls.NewListener(listener, &tls.Config{GetCertificate: getCertificate}), nil
	}
	return listener, nil
}

// acquireMCPListeners is the production local opt-in decision. It checks
// cancellation around each bind and closes every partial acquisition on failure.
func acquireMCPListeners(ctx context.Context, tailnet func() (net.Listener, error), localHTTP bool, localPort int, localListen func(string, string) (net.Listener, error)) ([]net.Listener, error) {
	open := []func() (net.Listener, error){tailnet}
	if localHTTP {
		open = append(open, func() (net.Listener, error) {
			return localListen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
		})
	}
	for i, bind := range open {
		open[i] = func() (net.Listener, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			listener, err := bind()
			if err != nil {
				return nil, err
			}
			if err := ctx.Err(); err != nil {
				return nil, errors.Join(err, listener.Close())
			}
			return listener, nil
		}
	}
	return acquireListeners(open...)
}

// Only the ready node's own identity is trusted, never CLI aliases, request
// headers, peer identity, or arbitrary names that happen to resolve to this node.
func tailnetHostMiddleware(next http.Handler, status *ipnstate.Status, port int, secure bool) (http.Handler, error) {
	hosts := make(map[string]bool)
	if status != nil {
		if status.Self != nil && status.Self.DNSName != "" {
			full := strings.ToLower(strings.TrimSuffix(status.Self.DNSName, "."))
			hosts[full] = true
			short, _, _ := strings.Cut(full, ".")
			hosts[short] = true
		}
		for _, ip := range status.TailscaleIPs {
			if ip.IsValid() {
				hosts[ip.Unmap().String()] = true
			}
		}
	}
	if len(hosts) == 0 {
		return nil, errors.New("tailnet status contains no canonical hosts")
	}
	scheme := "http"
	if secure {
		scheme = "https"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tuple, ok := parseOriginTuple(scheme + "://" + r.Host)
		host := tuple.host
		if ip, err := netip.ParseAddr(host); err == nil {
			host = ip.Unmap().String()
		}
		if !ok || tuple.port != port || !hosts[host] || (r.TLS != nil) != secure {
			http.Error(w, "forbidden tailnet host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}), nil
}

// Do not hide independent failures joined with an expected signal cancellation.
func expectedCancellation(ctx context.Context, err error) bool {
	if ctx.Err() != context.Canceled || err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if !expectedCancellation(ctx, child) {
				return false
			}
		}
		return true
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		return expectedCancellation(ctx, wrapped)
	}
	return err == context.Canceled
}

func endpointURL(host string, port int, tls bool) string {
	scheme := "http"
	if tls {
		scheme = "https"
	}
	return (&url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: mcpEndpointPath}).String()
}

func resolvePorts(port, localPort *int, tls, localHTTP, stdio bool) (tailnet, local int, err error) {
	for _, p := range []*int{port, localPort} {
		if p != nil && (*p < 1 || *p > 65535) {
			return 0, 0, errors.New("ports must be between 1 and 65535")
		}
	}
	if localPort != nil && !localHTTP {
		return 0, 0, errors.New("--local-port requires --local-http")
	}
	if stdio && (tls || localHTTP || port != nil || localPort != nil) {
		return 0, 0, errors.New("--stdio cannot be combined with HTTP listener options")
	}
	tailnet, local = 8080, 8080
	if tls {
		tailnet = 443
	}
	if port != nil {
		tailnet = *port
	}
	if localPort != nil {
		local = *localPort
	}
	return tailnet, local, nil
}

type originTuple struct {
	scheme, host string
	port         int
}

func parseOriginTuple(raw string) (originTuple, bool) {
	// Even empty query/fragment delimiters and a trailing slash are not origins.
	if strings.ContainsAny(raw, " \t\r\n,?#\\") {
		return originTuple{}, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.Path != "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return originTuple{}, false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(u.Host, ":") || strings.Contains(host, "%") {
		return originTuple{}, false
	}
	if (strings.Contains(host, ":") || strings.HasPrefix(u.Host, "[")) && (net.ParseIP(host) == nil || !strings.HasPrefix(u.Host, "[")) {
		return originTuple{}, false
	}
	if strings.HasPrefix(u.Host, "[") && !strings.Contains(host, ":") {
		return originTuple{}, false
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return originTuple{}, false
		}
	}
	return originTuple{u.Scheme, host, port}, true
}

func originAllowed(r *http.Request) bool {
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	origin, ok := parseOriginTuple(values[0])
	if !ok {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	expected, ok := parseOriginTuple(scheme + "://" + r.Host)
	return ok && origin == expected
}

func strictOriginMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !originAllowed(r) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bodyLimitMiddleware consumes a bounded body before any SDK dispatch. The read
// deadline bounds only body ingestion (the connection on HTTP/1, stream on HTTP/2).
func bodyLimitMiddleware(next http.Handler, timeout time.Duration) http.Handler {
	if timeout <= 0 {
		timeout = mcpBodyReadTimeout
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		if r.ContentLength > maxMCPBodyBytes {
			w.Header().Set("Connection", "close")
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		controller := http.NewResponseController(w)
		if err := controller.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			// Fail closed if a transport or wrapper cannot bound reads. Closing
			// the HTTP/1 connection also prevents net/http from draining the body.
			w.Header().Set("Connection", "close")
			http.Error(w, "cannot bound request body read", http.StatusInternalServerError)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMCPBodyBytes))
		clearErr := controller.SetReadDeadline(time.Time{})
		if err != nil {
			// Do not let net/http drain an incomplete body after clearing its
			// deadline; a stalled sender would otherwise delay this response.
			w.Header().Set("Connection", "close")
			status := http.StatusBadRequest
			var oversized *http.MaxBytesError
			var timedOut net.Error
			if errors.As(err, &oversized) {
				status = http.StatusRequestEntityTooLarge
			} else if errors.As(err, &timedOut) && timedOut.Timeout() {
				status = http.StatusRequestTimeout
			}
			http.Error(w, "invalid request body", status)
			return
		}
		if clearErr != nil {
			http.Error(w, "cannot clear request body deadline", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// acquireListeners does not start serving until every bind has succeeded.
func acquireListeners(open ...func() (net.Listener, error)) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, len(open))
	for i, bind := range open {
		listener, err := bind()
		if err != nil {
			for _, acquired := range listeners {
				err = errors.Join(err, acquired.Close())
			}
			return nil, fmt.Errorf("listen %d: %w", i, err)
		}
		listeners = append(listeners, listener)
	}
	return listeners, nil
}

type httpServerListener struct {
	Server   *http.Server
	Listener net.Listener
}

// serveHTTPServers owns the servers/listeners and their BaseContext. Call only
// after acquiring every listener; close tsnet after this returns. A nonpositive
// drainTimeout selects the production ten-second shared shutdown budget.
func serveHTTPServers(ctx context.Context, drainTimeout time.Duration, bindings ...httpServerListener) error {
	if len(bindings) == 0 {
		return errors.New("no HTTP listeners configured")
	}
	if err := ctx.Err(); err != nil {
		for _, binding := range bindings {
			err = errors.Join(err, binding.Listener.Close())
		}
		return err
	}
	if drainTimeout <= 0 {
		drainTimeout = mcpShutdownTimeout
	}
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	served := make(chan error, len(bindings))
	for i, binding := range bindings {
		binding.Server.BaseContext = func(net.Listener) context.Context { return requestCtx }
		go func() {
			err := binding.Server.Serve(binding.Listener)
			served <- fmt.Errorf("serve listener %d: %w", i, err)
		}()
	}
	var result error
	remaining := len(bindings)
	select {
	case <-ctx.Done():
	case err := <-served:
		remaining--
		if ctx.Err() == nil || !errors.Is(err, http.ErrServerClosed) {
			result = err
		}
	}
	cancel()
	drainCtx, drainCancel := context.WithTimeout(context.Background(), drainTimeout)
	defer drainCancel()
	drained := make(chan error, len(bindings))
	for i, binding := range bindings {
		go func() {
			err := binding.Server.Shutdown(drainCtx)
			if err != nil {
				err = fmt.Errorf("drain listener %d: %w", i, err)
			}
			err = errors.Join(err, binding.Server.Close())
			drained <- err
		}()
	}
	for range bindings {
		result = errors.Join(result, <-drained)
	}
	for range remaining {
		if err := <-served; !errors.Is(err, http.ErrServerClosed) {
			result = errors.Join(result, err)
		}
	}
	return result
}
