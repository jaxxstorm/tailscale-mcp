package mcpcoverage

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
)

func TestLoadOpenAPIEmitsEachOperationOnce(t *testing.T) {
	ops, err := LoadOpenAPI(filepath.Join("tailscale-v2-openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) == 0 {
		t.Fatal("expected operations")
	}

	seen := map[string]bool{}
	for _, op := range ops {
		if op.OperationID == "" {
			t.Fatalf("operation missing operationId: %#v", op)
		}
		if seen[op.OperationID] {
			t.Fatalf("duplicate operationId %q", op.OperationID)
		}
		seen[op.OperationID] = true
	}
}

func TestImplementedMappingsIncludeGrantPermissions(t *testing.T) {
	ops, err := LoadOpenAPI(filepath.Join("tailscale-v2-openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport("tailscale-v2-openapi.yaml", ops, CurrentMappings(), nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, record := range report.Operations {
		if record.Status != StatusImplemented {
			continue
		}
		if record.GrantPermission == "" {
			t.Fatalf("implemented mapping %s missing grant permission", record.Operation.OperationID)
		}
		if record.MCPName == "" && record.ResourceURI == "" {
			t.Fatalf("implemented mapping %s missing tool name or resource URI", record.Operation.OperationID)
		}
	}
}

func TestMutatingOperationsCannotBeResources(t *testing.T) {
	err := ValidateMapping(Operation{OperationID: "deleteDevice", Method: "DELETE", Path: "/device/{deviceId}"}, Mapping{OperationID: "deleteDevice", Type: MappingResource})
	if !errors.Is(err, ErrMutatingResource) {
		t.Fatalf("expected ErrMutatingResource, got %v", err)
	}
}

func TestReadEndpointDefinitionsHaveCoverageMappings(t *testing.T) {
	mappings := map[string]Mapping{}
	for _, mapping := range CurrentMappings() {
		mappings[mapping.OperationID] = mapping
	}
	for _, endpoint := range readapi.ToolEndpoints() {
		mapping, ok := mappings[endpoint.OperationID]
		if !ok {
			t.Fatalf("missing coverage mapping for %q", endpoint.OperationID)
		}
		if mapping.Name == "" && mapping.URI == "" {
			t.Fatalf("mapping for %q has no MCP name or URI", endpoint.OperationID)
		}
	}
}

func TestMutatingEndpointMappingsIncludeConfirmation(t *testing.T) {
	mappings := map[string]Mapping{}
	for _, mapping := range CurrentMappings() {
		mappings[mapping.OperationID] = mapping
	}
	for _, endpoint := range readapi.MutatingEndpoints() {
		mapping, ok := mappings[endpoint.OperationID]
		if !ok {
			t.Fatalf("missing coverage mapping for %q", endpoint.OperationID)
		}
		if mapping.GrantPermission == "" {
			t.Fatalf("mapping for %q missing grant permission", endpoint.OperationID)
		}
		if mapping.Confirmation != endpoint.Confirm {
			t.Fatalf("mapping for %q confirmation = %q, want %q", endpoint.OperationID, mapping.Confirmation, endpoint.Confirm)
		}
	}
}

func TestToolMappingsIncludeExpectedSafetyHints(t *testing.T) {
	mappings := map[string][]Mapping{}
	for _, mapping := range CurrentMappings() {
		mappings[mapping.OperationID] = append(mappings[mapping.OperationID], mapping)
	}

	coreReadTools := map[string]bool{
		"listTailnetDevices": true,
		"getDevice":          true,
	}
	for operationID := range coreReadTools {
		mapping, ok := toolMapping(mappings[operationID])
		if !ok {
			t.Fatalf("missing coverage mapping for %q", operationID)
		}
		if !mapping.ReadOnly || mapping.Destructive || !mapping.Idempotent {
			t.Fatalf("core mapping %q hints = readOnly:%v destructive:%v idempotent:%v, want readOnly:true destructive:false idempotent:true", operationID, mapping.ReadOnly, mapping.Destructive, mapping.Idempotent)
		}
	}

	for _, endpoint := range readapi.ToolEndpoints() {
		mapping, ok := toolMapping(mappings[endpoint.OperationID])
		if !ok {
			t.Fatalf("missing coverage mapping for %q", endpoint.OperationID)
		}
		hints := endpoint.ToolHints()
		if mapping.ReadOnly != hints.ReadOnly || mapping.Destructive != hints.Destructive || mapping.Idempotent != hints.Idempotent {
			t.Fatalf("mapping %q hints = readOnly:%v destructive:%v idempotent:%v, want readOnly:%v destructive:%v idempotent:%v", endpoint.OperationID, mapping.ReadOnly, mapping.Destructive, mapping.Idempotent, hints.ReadOnly, hints.Destructive, hints.Idempotent)
		}
	}
}

func TestCuratedToolsAreNotCanonicalCoverageMappings(t *testing.T) {
	for _, mapping := range CurrentMappings() {
		if strings.HasSuffix(mapping.Name, "_curated") || strings.HasPrefix(mapping.Name, "tailscale_device_") || mapping.Name == "tailscale_status" || mapping.Name == "tailscale_get_acl" {
			t.Fatalf("curated tool %q must not be counted as canonical OpenAPI coverage", mapping.Name)
		}
	}
}

func toolMapping(mappings []Mapping) (Mapping, bool) {
	for _, mapping := range mappings {
		if mapping.Type == MappingTool && mapping.Name != "" {
			return mapping, true
		}
	}
	return Mapping{}, false
}

func TestExclusionsRequireReason(t *testing.T) {
	_, err := BuildReport("test", []Operation{{OperationID: "listDevices", Method: "GET", Path: "/devices"}}, nil, map[string]Exclusion{
		"listDevices": {OperationID: "listDevices"},
	})
	if err == nil {
		t.Fatal("expected invalid exclusion to be rejected")
	}
}
