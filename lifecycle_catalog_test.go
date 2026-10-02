package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
	"github.com/jaxxstorm/tailscale-mcp/internal/toolmeta"
	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/oauth2"
)

var lifecycleCatalogCases = []struct {
	name, operationID                 string
	readOnly, destructive, idempotent bool
}{
	{"tailscale_list_organization_tailnets", "listOrganizationTailnets", true, false, true},
	{"tailscale_create_organization_tailnet", "createOrganizationTailnet", false, false, false},
	{"tailscale_delete_tailnet", "deleteTailnet", false, true, true},
}

func TestLifecycleCatalogCompleteness(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprint(local), func(t *testing.T) {
			s, catalog, err := newConfiguredMCPServer(nil, readapi.Client{}, local)
			if err != nil {
				t.Fatal(err)
			}
			if err := catalog.Validate(s.ListTools()); err != nil {
				t.Fatal(err)
			}
			for _, want := range lifecycleCatalogCases {
				count := 0
				for _, metadata := range catalog.Tools() {
					if metadata.Name == want.name {
						count++
						if metadata.Group != "organizations" || metadata.ReadOnly != want.readOnly {
							t.Errorf("%s: metadata = %+v", want.name, metadata)
						}
					}
				}
				if count != 1 {
					t.Errorf("%s: catalog occurrences = %d, want 1", want.name, count)
				}
				tool := s.GetTool(want.name)
				if tool == nil {
					t.Errorf("missing registration: %s", want.name)
					continue
				}
				hints := tool.Tool.Annotations
				if hints.ReadOnlyHint == nil || *hints.ReadOnlyHint != want.readOnly ||
					hints.DestructiveHint == nil || *hints.DestructiveHint != want.destructive ||
					hints.IdempotentHint == nil || *hints.IdempotentHint != want.idempotent {
					t.Errorf("%s: incorrect hints: %+v", want.name, hints)
				}
			}
		})
	}
}

func TestLifecycleCatalogGrantsAndExecution(t *testing.T) {
	var calls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer test-only-all-scope" {
			t.Error("configured credential not used")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /organizations/test-org/tailnets":
			_, _ = w.Write([]byte(`{"tailnets":[],"totalCount":0}`))
		case "POST /organizations/test-org/tailnets":
			_, _ = w.Write([]byte(`{"id":"new-tailnet","oauthClient":{"secret":"test-only-created-secret"}}`))
		case "DELETE /tailnet/test-tailnet":
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected upstream call: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer api.Close()
	// The mock accepts all lifecycle operations with this upstream all-scope
	// credential. Neither its scope nor its presence supplies MCP caller grants.
	token := (&oauth2.Token{AccessToken: "test-only-all-scope"}).WithExtra(map[string]any{"scope": "all"})
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, api.Client())
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	s, catalog, err := newConfiguredMCPServer(nil, readapi.Client{BaseURL: api.URL, Tailnet: "test-tailnet", HTTPClient: client}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range lifecycleCatalogCases {
		if s.GetTool(tool.name) == nil {
			t.Fatalf("missing lifecycle registration: %s", tool.name)
		}
	}
	for _, tc := range []struct {
		name      string
		selectors []string
		allowed   [3]bool
		listCount int
	}{
		{"upstream scope without MCP grants", nil, [3]bool{}, 0},
		{"exact listing", []string{lifecycleCatalogCases[0].name}, [3]bool{true, false, false}, 1},
		{"exact creation", []string{lifecycleCatalogCases[1].name}, [3]bool{false, true, false}, 1},
		{"exact deletion", []string{lifecycleCatalogCases[2].name}, [3]bool{false, false, true}, 1},
		{"global", []string{"*"}, [3]bool{true, true, true}, -1},
		{"global read", []string{"read:*"}, [3]bool{true, false, false}, -1},
		{"organizations", []string{"group:organizations"}, [3]bool{true, true, true}, 3},
		{"organizations read", []string{"group:organizations:read"}, [3]bool{true, false, false}, 1},
		{"tailnet isolation", []string{"group:tailnet"}, [3]bool{}, -1},
		{"tailnet read isolation", []string{"group:tailnet:read"}, [3]bool{}, -1},
		{"OAuth scopes are not selectors", []string{"tailnets:read", "tailnets", "all"}, [3]bool{}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := withCapabilities(context.Background(), &MCPCapability{Tools: tc.selectors}, tc.name)
			response := dispatchGrantTest(t, s, ctx, "tools/list", map[string]any{})
			rpc, ok := response.(mcp.JSONRPCResponse)
			if !ok {
				t.Fatalf("discovery failed: %#v", response)
			}
			listed := rpc.Result.(mcp.ListToolsResult).Tools
			if tc.listCount >= 0 && len(listed) != tc.listCount {
				t.Errorf("discovered %d tools, want %d", len(listed), tc.listCount)
			}
			visible := map[string]bool{}
			for _, tool := range listed {
				visible[tool.Name] = true
			}
			for i, tool := range lifecycleCatalogCases {
				t.Run(tool.name, func(t *testing.T) {
					allowed := tc.allowed[i]
					if catalog.Allows(tc.selectors, tool.name) != allowed || visible[tool.name] != allowed {
						t.Errorf("catalog/discovery mismatch: allowed=%v visible=%v, want %v", catalog.Allows(tc.selectors, tool.name), visible[tool.name], allowed)
					}
					args := map[string]any{"organization": "test-org"}
					if i == 1 {
						args["body"] = map[string]any{"displayName": "Test tailnet"}
					}
					if i == 2 {
						args = map[string]any{"tailnet": "test-tailnet"}
					}
					if !tool.readOnly {
						args["confirm"] = tool.operationID
					}
					before := calls.Load()
					response := dispatchGrantTest(t, s, ctx, "tools/call", map[string]any{"name": tool.name, "arguments": args})
					if !allowed {
						if _, ok := response.(mcp.JSONRPCError); !ok {
							t.Errorf("hidden tool dispatch was not denied: %#v", response)
						}
						// Bypass discovery/dispatch and exercise the registered handler check.
						req := mcp.CallToolRequest{}
						req.Params.Name, req.Params.Arguments = tool.name, args
						result, err := s.GetTool(tool.name).Handler(ctx, req)
						if err == nil && (result == nil || !result.IsError) {
							t.Errorf("direct handler bypassed grants: %+v", result)
						}
						if calls.Load() != before {
							t.Fatal("denied lifecycle call contacted upstream")
						}
						return
					}
					rpc, ok := response.(mcp.JSONRPCResponse)
					if !ok || rpc.Result.(*mcp.CallToolResult).IsError || calls.Load() != before+1 {
						t.Fatalf("authorized call failed: %#v; upstream calls=%d", response, calls.Load()-before)
					}
					if tool.readOnly {
						return
					}
					if i == 2 {
						args["tailnet"] = "different-tailnet"
						before := calls.Load()
						response := dispatchGrantTest(t, s, ctx, "tools/call", map[string]any{"name": tool.name, "arguments": args})
						rpc, ok := response.(mcp.JSONRPCResponse)
						if !ok || !rpc.Result.(*mcp.CallToolResult).IsError || calls.Load() != before {
							t.Fatalf("grant bypassed configured-target acknowledgement: %#v", response)
						}
						args["tailnet"] = "test-tailnet"
					}
					for _, confirmation := range []string{"", "wrong-operation"} {
						delete(args, "confirm")
						if confirmation != "" {
							args["confirm"] = confirmation
						}
						before := calls.Load()
						response := dispatchGrantTest(t, s, ctx, "tools/call", map[string]any{"name": tool.name, "arguments": args})
						rpc, ok := response.(mcp.JSONRPCResponse)
						if !ok || !rpc.Result.(*mcp.CallToolResult).IsError {
							t.Errorf("confirmation %q bypassed: %#v", confirmation, response)
						}
						req := mcp.CallToolRequest{}
						req.Params.Name, req.Params.Arguments = tool.name, args
						result, err := s.GetTool(tool.name).Handler(ctx, req)
						if err == nil && (result == nil || !result.IsError) {
							t.Errorf("direct handler bypassed confirmation %q", confirmation)
						}
						if calls.Load() != before {
							t.Fatal("unconfirmed mutation contacted upstream")
						}
					}
				})
			}
		})
	}
}

func TestLifecycleOfflineGroupListing(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprint(local), func(t *testing.T) {
			args := []string{"--list-groups"}
			if local {
				args = append(args, "--local-cli")
			}
			var previous []byte
			for range 2 {
				// This harness clears credentials, isolates state, and rejects HTTP.
				cmd, stderr := startupCommand(t, "offline", args...)
				output, err := cmd.Output()
				if err != nil {
					t.Fatalf("offline --list-groups: %v\n%s", err, stderr)
				}
				if previous != nil && !bytes.Equal(previous, output) {
					t.Fatal("nondeterministic offline group listing")
				}
				previous = output
				var tools []toolmeta.Tool
				if err := json.Unmarshal(output, &tools); err != nil {
					t.Fatal(err)
				}
				for i := 1; i < len(tools); i++ {
					if tools[i-1].Name >= tools[i].Name {
						t.Fatal("group listing is not uniquely sorted by name")
					}
				}
				for _, want := range lifecycleCatalogCases {
					count := 0
					for _, tool := range tools {
						if tool.Name == want.name {
							count++
							if tool.Group != "organizations" || tool.ReadOnly != want.readOnly {
								t.Errorf("offline metadata: %+v", tool)
							}
						}
					}
					if count != 1 {
						t.Errorf("%s: offline occurrences=%d, want 1", want.name, count)
					}
				}
				if strings.Contains(string(output), "tailscale_ping") != local {
					t.Fatal("offline listing ignored local CLI opt-in")
				}
			}
		})
	}
}
