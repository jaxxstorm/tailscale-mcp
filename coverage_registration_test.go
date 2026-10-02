package main

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
	mcpcoverage "github.com/jaxxstorm/tailscale-mcp/tools/coverage"
	"github.com/mark3labs/mcp-go/mcp"
)

func TestCoverageClaimsHaveProductionRegistrations(t *testing.T) {
	s, _, err := newConfiguredMCPServer(nil, readapi.Client{}, false)
	if err != nil {
		t.Fatal(err)
	}
	response := dispatchGrantTest(t, s, context.Background(), "resources/templates/list", map[string]any{})
	rpc, ok := response.(mcp.JSONRPCResponse)
	if !ok {
		t.Fatalf("resource template discovery failed: %#v", response)
	}
	data, err := json.Marshal(rpc.Result)
	if err != nil {
		t.Fatal(err)
	}
	var templates mcp.ListResourceTemplatesResult
	if err := json.Unmarshal(data, &templates); err != nil {
		t.Fatal(err)
	}
	resources := map[string]bool{}
	for uri := range s.ListResources() {
		resources[uri] = true
	}
	for _, template := range templates.ResourceTemplates {
		resources[template.URITemplate.Raw()] = true
	}
	// Check every claim, not just the last mapping chosen for each report row.
	for _, mapping := range mcpcoverage.CurrentMappings() {
		switch mapping.Type {
		case mcpcoverage.MappingTool:
			tool := s.GetTool(mapping.Name)
			if tool == nil || tool.Handler == nil {
				t.Errorf("%s claims unregistered tool %q", mapping.OperationID, mapping.Name)
				continue
			}
			if mapping.GrantPermission != "tool:"+mapping.Name {
				t.Errorf("%s: grant does not match registered tool", mapping.OperationID)
			}
			hints := tool.Tool.Annotations
			if hints.ReadOnlyHint == nil || *hints.ReadOnlyHint != mapping.ReadOnly || hints.DestructiveHint == nil || *hints.DestructiveHint != mapping.Destructive || hints.IdempotentHint == nil || *hints.IdempotentHint != mapping.Idempotent {
				t.Errorf("%s: registered hints disagree with coverage", mapping.OperationID)
			}
			if mapping.Confirmation != "" {
				property, ok := tool.Tool.InputSchema.Properties["confirm"].(map[string]any)
				description, _ := property["description"].(string)
				if !ok || !strings.Contains(description, mapping.Confirmation) || !slices.Contains(tool.Tool.InputSchema.Required, "confirm") {
					t.Errorf("%s: registered confirmation disagrees with coverage", mapping.OperationID)
				}
			}
			switch mapping.OperationID {
			case "listOrganizationTailnets", "createOrganizationTailnet", "deleteTailnet":
				if !strings.Contains(tool.Tool.Description, "Alpha") {
					t.Errorf("%s: registered description missing Alpha warning", mapping.OperationID)
				}
			}
		case mcpcoverage.MappingResource:
			if !resources[mapping.URI] {
				t.Errorf("%s claims unregistered resource %q", mapping.OperationID, mapping.URI)
			}
			if mapping.GrantPermission != "resource:"+mapping.URI {
				t.Errorf("%s: grant does not match registered resource", mapping.OperationID)
			}
		default:
			t.Errorf("%s has unsupported implementation claim %q", mapping.OperationID, mapping.Type)
		}
	}
}
