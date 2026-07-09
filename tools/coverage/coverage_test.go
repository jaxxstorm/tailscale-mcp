package mcpcoverage

import (
	"errors"
	"path/filepath"
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

func TestExclusionsRequireReason(t *testing.T) {
	_, err := BuildReport("test", []Operation{{OperationID: "listDevices", Method: "GET", Path: "/devices"}}, nil, map[string]Exclusion{
		"listDevices": {OperationID: "listDevices"},
	})
	if err == nil {
		t.Fatal("expected invalid exclusion to be rejected")
	}
}
