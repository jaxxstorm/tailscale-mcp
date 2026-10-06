package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jaxxstorm/tailscale-mcp/internal/aperture"
	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
	"github.com/mark3labs/mcp-go/mcp"
)

func TestApertureProductionContractCoverage(t *testing.T) {
	data, err := os.ReadFile("tools/aperture/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Paths map[string]map[string]struct {
			ID string `json:"operationId"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	s, catalog, err := newApertureMCPServer(aperture.Client{})
	if err != nil {
		t.Fatal(err)
	}
	mapped := map[string]bool{}
	for _, op := range aperture.Operations() {
		key := op.Method + " " + op.Path
		if mapped[key] || schema.Paths[op.Path][strings.ToLower(op.Method)].ID != op.OperationID {
			t.Fatalf("duplicate or stale mapping: %+v", op)
		}
		mapped[key] = true
		tool := s.GetTool(op.ToolName)
		if tool == nil || op.ToolName != "aperture_"+strings.ReplaceAll(op.OperationID, "-", "_") {
			t.Fatalf("unregistered or inconsistent permission: %+v", op)
		}
		if !catalog.Allows([]string{"group:" + op.Group}, op.ToolName) || catalog.Allows([]string{"read:*"}, op.ToolName) != op.ReadOnly {
			t.Fatalf("metadata mismatch: %+v", op)
		}
		if op.ReadOnly != (op.Method != "PUT") {
			t.Fatalf("mutation classification mismatch: %+v", op)
		}
	}
	count := 0
	for path, methods := range schema.Paths {
		for method := range methods {
			if !mapped[strings.ToUpper(method)+" "+path] {
				t.Errorf("unmapped operation: %s %s", method, path)
			}
			count++
		}
	}
	if count != 5 || len(s.ListTools()) != count {
		t.Fatalf("expected five operations, got schema=%d tools=%d", count, len(s.ListTools()))
	}
	if err := catalog.Validate(s.ListTools()); err != nil {
		t.Fatal(err)
	}
}

func TestApertureCatalogAuthorization(t *testing.T) {
	var calls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("ETag", `"current"`)
		fmt.Fprint(w, `{"config":"{}"}`)
	}))
	defer api.Close()
	client, err := aperture.NewClient(api.URL+"/aperture", api.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	s, catalog, err := newApertureMCPServer(client)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		selectors []string
		count     int
	}{
		{nil, 0}, {[]string{"aperture_get_config"}, 1}, {[]string{"*"}, 5},
		{[]string{"read:*"}, 4}, {[]string{"group:aperture-config"}, 3},
		{[]string{"group:aperture-config:read"}, 2}, {[]string{"group:aperture-pricing"}, 2},
		{[]string{"group:aperture-pricing:read"}, 2}, {[]string{"group:unknown"}, 0},
		{[]string{"group:dns", "get_device_info", "tailscale_get_dns_configuration"}, 0},
		{[]string{"aperture:*"}, 0},
	} {
		t.Run(fmt.Sprint(tc.selectors), func(t *testing.T) {
			ctx := withCapabilities(context.Background(), &MCPCapability{Tools: tc.selectors}, "caller")
			response := dispatchGrantTest(t, s, ctx, "tools/list", map[string]any{})
			listed := response.(mcp.JSONRPCResponse).Result.(mcp.ListToolsResult).Tools
			if len(listed) != tc.count {
				t.Fatalf("listed %d tools, want %d", len(listed), tc.count)
			}
			for _, tool := range catalog.Tools() {
				if catalog.Allows(tc.selectors, tool.Name) {
					continue
				}
				args := map[string]any{"config": "{}", "confirm": "aperture_set_config", "if_match": `"current"`, "model": "provider/model"}
				before := calls.Load()
				response := dispatchGrantTest(t, s, ctx, "tools/call", map[string]any{"name": tool.Name, "arguments": args})
				if _, ok := response.(mcp.JSONRPCError); !ok {
					t.Fatalf("unauthorized tool dispatched: %#v", response)
				}
				request := mcp.CallToolRequest{}
				request.Params.Name, request.Params.Arguments = tool.Name, args
				result, err := s.GetTool(tool.Name).Handler(ctx, request)
				if err == nil && (result == nil || !result.IsError) {
					t.Fatal("direct handler bypassed authorization")
				}
				if calls.Load() != before {
					t.Fatal("denial contacted Aperture")
				}
			}
		})
	}
	// A single SDK session cannot retain the previous request's grants.
	session := &grantTestSession{notifications: make(chan mcp.JSONRPCNotification, 10)}
	if err := s.RegisterSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	defer s.UnregisterSession(context.Background(), session.SessionID())
	base := s.WithContext(context.Background(), session)
	for _, allowed := range []bool{true, false, true, false} {
		caps := &MCPCapability{}
		if allowed {
			caps.Tools = []string{"aperture_get_config"}
		}
		ctx := withCapabilities(base, caps, "caller")
		response := dispatchGrantTest(t, s, ctx, "tools/list", map[string]any{})
		listed := response.(mcp.JSONRPCResponse).Result.(mcp.ListToolsResult).Tools
		if (len(listed) == 1) != allowed || len(listed) > 1 {
			t.Fatal("discovery retained session grants")
		}
		before := calls.Load()
		response = dispatchGrantTest(t, s, ctx, "tools/call", map[string]any{"name": "aperture_get_config"})
		_, denied := response.(mcp.JSONRPCError)
		if denied == allowed || (calls.Load() == before+1) != allowed {
			t.Fatal("execution retained session grants")
		}
	}
}

func TestApertureIndependentCatalogs(t *testing.T) {
	for i := range 8 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			ts, tc, err := newConfiguredMCPServer(nil, readapi.Client{}, i%2 == 0)
			if err != nil {
				t.Fatal(err)
			}
			as, ac, err := newApertureMCPServer(aperture.Client{})
			if err != nil {
				t.Fatal(err)
			}
			if tc.Allows([]string{"*"}, "aperture_get_config") || ac.Allows([]string{"*"}, "list_all_devices") {
				t.Fatal("cross-service catalog leakage")
			}
			if err := tc.Validate(ts.ListTools()); err != nil {
				t.Fatal(err)
			}
			if err := ac.Validate(as.ListTools()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOfflineApertureCatalogSelection(t *testing.T) {
	for _, stdio := range []bool{false, true} {
		var first, second bytes.Buffer
		if err := writeToolGroups(&first, false, stdio); err != nil {
			t.Fatal(err)
		}
		if err := writeToolGroups(&second, false, stdio); err != nil {
			t.Fatal(err)
		}
		if first.String() != second.String() || strings.Contains(first.String(), "aperture_get_config") == stdio {
			t.Fatal("offline catalog is nondeterministic or includes wrong service")
		}
	}
}
