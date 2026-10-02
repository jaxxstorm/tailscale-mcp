package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/jaxxstorm/tailscale-mcp/internal/toolmeta"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// Standalone probe servers in tests still use the production catalog evaluator.
func checkToolAccess(ctx context.Context, name string) error {
	catalog, err := toolmeta.New([]toolmeta.Tool{{Name: name, Group: "test"}})
	if err != nil {
		return err
	}
	return toolAccessChecker(catalog)(ctx, name)
}

func TestPeerCapabilityUnion(t *testing.T) {
	caps, err := capabilitiesFromPeer(tailcfg.PeerCapMap{mcpCapabilityKey: {
		`{"tools":["one","one"],"resources":["tailscale://devices"]}`,
		`{"tools":["two","one"],"resources":["tailscale://devices/*","tailscale://devices"]}`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(caps, MCPCapability{Tools: []string{"one", "two"}, Resources: []string{"tailscale://devices", "tailscale://devices/*"}}) {
		t.Fatalf("union = %#v", caps)
	}
	for _, raw := range []tailcfg.RawMessage{`{`, `{"tools":42}`, `{"resources":[{}]}`, `[]`, `null`, `{"tools":["*",null]}`, `{"tools":["*"],"resources":null}`, `{"tools":null}`, `{"Tools":["*"]}`, `{"unknown":true}`, `{"tools":[],"tools":["*"]}`} {
		got, err := capabilitiesFromPeer(tailcfg.PeerCapMap{mcpCapabilityKey: {`{"tools":["*"]}`, raw}})
		if err == nil || len(got.Tools) != 0 {
			t.Errorf("malformed entry %s did not fail closed", raw)
		}
	}
	for _, peer := range []tailcfg.PeerCapMap{nil, {}, {"other": {`{"tools":["*"]}`}}} {
		got, err := capabilitiesFromPeer(peer)
		if err != nil || len(got.Tools)+len(got.Resources) != 0 {
			t.Fatalf("missing grants: %#v, %v", got, err)
		}
	}
}

func TestMalformedCapabilityShapesRejectBeforeDispatch(t *testing.T) {
	for _, raw := range []tailcfg.RawMessage{
		`{"tools":["*",null]}`, `{"tools":["*"],"resources":null}`,
		`{"tools":null}`, `{"resources":[null]}`, `{"Tools":["*"]}`,
		`{"tools":[],"tools":["*"]}`, `{"unknown":true}`,
	} {
		for _, withValid := range []bool{false, true} {
			entries := []tailcfg.RawMessage{raw}
			if withValid {
				entries = append(entries, `{"tools":["*"],"resources":["*"]}`)
			}
			called := false
			h := peerGrantMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			}), func(context.Context, string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{CapMap: tailcfg.PeerCapMap{mcpCapabilityKey: entries}}, nil
			})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp", nil))
			if w.Code != http.StatusForbidden || called {
				t.Errorf("entry %s withValid=%v: status=%d dispatched=%v", raw, withValid, w.Code, called)
			}
		}
	}
}

func TestTypedGrantsSnapshot(t *testing.T) {
	if _, _, err := getTailscaleCapabilities(context.Background()); err == nil {
		t.Fatal("missing context accepted")
	}
	caps := &MCPCapability{Tools: []string{"one"}}
	ctx := withCapabilities(context.Background(), caps, "alice")
	caps.Tools[0] = "*"
	got, user, err := getTailscaleCapabilities(ctx)
	if err != nil || user != "alice" || got.Tools[0] != "one" {
		t.Fatal("context did not snapshot grants")
	}
	got.Tools[0] = "*"
	got, _, _ = getTailscaleCapabilities(ctx)
	if got.Tools[0] != "one" {
		t.Fatal("context leaked mutable grants")
	}
}

func TestResourceBoundaries(t *testing.T) {
	for _, tc := range []struct {
		selector, uri string
		want          bool
	}{
		{"", "tailscale://devices", false}, {"", "", false},
		{"tailscale://device", "tailscale://device", true},
		{"tailscale://device", "tailscale://devices", false},
		{"tailscale://device", "tailscale://device/123", false},
		{"tailscale://devices/*", "tailscale://devices/123", true},
		{"tailscale://devices/*", "tailscale://devices/123/details", true},
		{"tailscale://devices/*", "tailscale://devices", false},
		{"tailscale://devices/*", "tailscale://devices/", false},
		{"tailscale://devices/*", "tailscale://devices-other/123", false},
		{"tailscale://devices*", "tailscale://devices/123", false},
		{"*", "tailscale://devices", true},
	} {
		ctx := withCapabilities(context.Background(), &MCPCapability{Resources: []string{tc.selector}}, "alice")
		if got := checkResourceAccess(ctx, tc.uri) == nil; got != tc.want {
			t.Errorf("%q -> %q: %v", tc.selector, tc.uri, got)
		}
	}
	ctx := withCapabilities(context.Background(), &MCPCapability{Tools: []string{"*", "read:*", "group:devices"}}, "alice")
	if checkResourceAccess(ctx, "tailscale://devices") == nil {
		t.Fatal("tool permission granted resource access")
	}
}

func TestPeerGrantMiddleware(t *testing.T) {
	for _, tc := range []struct {
		name    string
		who     *apitype.WhoIsResponse
		err     error
		status  int
		allowed bool
	}{
		{"missing", &apitype.WhoIsResponse{}, nil, 200, false},
		{"invalid", &apitype.WhoIsResponse{CapMap: tailcfg.PeerCapMap{mcpCapabilityKey: {`{"tools":["*"]}`, `{`}}}, nil, 403, false},
		{"identity error", nil, errors.New("lookup failed"), 401, false},
		{"union", &apitype.WhoIsResponse{CapMap: tailcfg.PeerCapMap{mcpCapabilityKey: {`{"tools":["one"]}`, `{"tools":["two"]}`}}}, nil, 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := peerGrantMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if got := checkToolAccess(r.Context(), "two") == nil; got != tc.allowed {
					t.Errorf("access = %v", got)
				}
			}), func(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
				if addr != "100.64.0.1:1234" {
					t.Errorf("identity lookup trusted wrong address: %s", addr)
				}
				return tc.who, tc.err
			})
			r := httptest.NewRequest("POST", "/mcp", nil)
			r.RemoteAddr = "100.64.0.1:1234"
			r.Header.Set("X-Tailscale-User", "admin")
			r.Header.Set("X-Tailscale-Grants", `{"tools":["*"]}`)
			r.Header.Set("X-Forwarded-For", "100.64.0.2")
			// A tailnet lookup must also replace any preexisting local context.
			r = r.WithContext(withCapabilities(r.Context(), &MCPCapability{Tools: []string{"*"}}, "local"))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || called != (tc.status == 200) {
				t.Fatalf("status=%d dispatched=%v", w.Code, called)
			}
		})
	}
}
