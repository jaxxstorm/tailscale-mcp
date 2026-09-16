package main

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/jaxxstorm/tailscale-mcp/internal/toolmeta"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

const mcpCapabilityKey = "jaxxstorm.com/cap/mcp"

// Apply the same strict shape validation to peer grants and local configuration.
// encoding/json otherwise accepts null string elements and case-insensitive keys.
func (c *MCPCapability) UnmarshalJSON(data []byte) error {
	parsed, err := parseLocalGrants(string(data))
	if err != nil || parsed == nil {
		return errors.New("invalid MCP capability object")
	}
	*c = *parsed
	return nil
}

type grantContextKey struct{}
type requestGrants struct {
	capability MCPCapability
	user       string
}

// withCapabilities is for trusted transport configuration, never client headers.
func withCapabilities(ctx context.Context, caps *MCPCapability, user string) context.Context {
	var snapshot MCPCapability
	if caps != nil {
		snapshot.Tools = slices.Clone(caps.Tools)
		snapshot.Resources = slices.Clone(caps.Resources)
	}
	return context.WithValue(ctx, grantContextKey{}, requestGrants{snapshot, user})
}

func capabilitiesFromPeer(caps tailcfg.PeerCapMap) (MCPCapability, error) {
	entries, err := tailcfg.UnmarshalCapJSON[*MCPCapability](caps, mcpCapabilityKey)
	if err != nil {
		return MCPCapability{}, errors.New("invalid MCP capabilities")
	}
	var union MCPCapability
	for _, entry := range entries {
		if entry == nil {
			return MCPCapability{}, errors.New("invalid MCP capabilities")
		}
		for _, tool := range entry.Tools {
			if !slices.Contains(union.Tools, tool) {
				union.Tools = append(union.Tools, tool)
			}
		}
		for _, resource := range entry.Resources {
			if !slices.Contains(union.Resources, resource) {
				union.Resources = append(union.Resources, resource)
			}
		}
	}
	return union, nil
}

func toolAccessChecker(catalog *toolmeta.Catalog) func(context.Context, string) error {
	return func(ctx context.Context, name string) error {
		caps, user, err := getTailscaleCapabilities(ctx)
		if err == nil && catalog.Allows(caps.Tools, name) {
			return nil
		}
		var selectors []string
		if caps != nil {
			selectors = caps.Tools
		}
		return errors.New(createPermissionErrorJSON(user, name, "tool", selectors))
	}
}

func resourceAllowed(selectors []string, uri string) bool {
	if uri == "" {
		return false
	}
	for _, selector := range selectors {
		if selector == "" {
			continue
		}
		if selector == "*" || selector == uri {
			return true
		}
		if strings.HasSuffix(selector, "/*") {
			prefix := strings.TrimSuffix(selector, "*")
			if strings.HasPrefix(uri, prefix) && len(uri) > len(prefix) {
				return true
			}
		}
	}
	return false
}

type whoIsFunc func(context.Context, string) (*apitype.WhoIsResponse, error)

func peerGrantMiddleware(next http.Handler, whoIs whoIsFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, err := whoIs(r.Context(), r.RemoteAddr)
		if err != nil || who == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		caps, err := capabilitiesFromPeer(who.CapMap)
		if err != nil {
			http.Error(w, "invalid MCP capabilities", http.StatusForbidden)
			return
		}
		user := "unknown"
		if who.UserProfile != nil {
			user = who.UserProfile.LoginName
		}
		next.ServeHTTP(w, r.WithContext(withCapabilities(r.Context(), &caps, user)))
	})
}
