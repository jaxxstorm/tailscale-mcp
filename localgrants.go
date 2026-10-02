package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/server"
)

// parseLocalGrants accepts a single capability object, not a tailnet capability map.
func parseLocalGrants(raw string) (*MCPCapability, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("local grants must be a JSON object with tools and/or resources arrays")
	}
	caps := &MCPCapability{}
	seen := make(map[string]bool)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid local grants: %w", err)
		}
		key, ok := token.(string)
		if !ok || (key != "tools" && key != "resources") || seen[key] {
			return nil, errors.New("local grants contain an unknown or duplicate field")
		}
		seen[key] = true
		var values []json.RawMessage
		if err := dec.Decode(&values); err != nil || values == nil {
			return nil, fmt.Errorf("local grants %s must be an array of strings", key)
		}
		selectors := make([]string, 0, len(values))
		for _, value := range values {
			var selector string
			if string(value) == "null" || json.Unmarshal(value, &selector) != nil {
				return nil, fmt.Errorf("local grants %s must contain only strings", key)
			}
			selectors = append(selectors, selector)
		}
		if key == "tools" {
			caps.Tools = selectors
		} else {
			caps.Resources = selectors
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("invalid local grants: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("local grants must contain exactly one JSON object")
	}
	return caps, nil
}

func validateLocalHTTP(localHTTP, stdio bool, caps *MCPCapability) error {
	if !localHTTP {
		return nil
	}
	if stdio {
		return errors.New("--local-http cannot be used with --stdio")
	}
	if caps != nil {
		for _, selectors := range [][]string{caps.Tools, caps.Resources} {
			for _, selector := range selectors {
				if strings.TrimSpace(selector) != "" {
					return nil
				}
			}
		}
	}
	return errors.New("--local-http requires non-empty --local-grants (TS_MCP_LOCAL_GRANTS)")
}

func stdioContextFunc(caps *MCPCapability) server.StdioContextFunc {
	return func(ctx context.Context) context.Context {
		return withCapabilities(ctx, caps, "local-stdio")
	}
}

// localGrantMiddleware is only for the explicitly enabled loopback listener.
// Host validation is independent of Origin equality to prevent DNS rebinding.
func localGrantMiddleware(next http.Handler, caps *MCPCapability) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := parseOriginTuple("http://" + r.Host)
		// net/http supplies the actual bound address, independent of request headers.
		local, _ := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
		if !ok || local == nil || u.port != local.Port || (u.host != "localhost" && u.host != "127.0.0.1" && u.host != "::1") {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !net.ParseIP(peer).IsLoopback() {
			http.Error(w, "forbidden peer", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(withCapabilities(r.Context(), caps, "local-http")))
	})
}
