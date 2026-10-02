package mcpcoverage

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
)

func snapshotReport(t *testing.T) Report {
	t.Helper()
	ops, err := LoadOpenAPI("tailscale-v2-openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport("tailscale-v2-openapi.yaml", ops, CurrentMappings(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestSnapshotCoverageComplete(t *testing.T) {
	report := snapshotReport(t)
	if report.Summary.Total == 0 {
		t.Fatal("empty snapshot")
	}
	for _, record := range report.Operations {
		if record.Status != StatusImplemented {
			t.Errorf("%s: expected implemented mapping, got %s", record.Operation.OperationID, record.Status)
		}
	}
	// Deliberately inventory the snapshot rather than freezing future coverage at 93.
	if report.Summary.Implemented != report.Summary.Total || report.Summary.Gaps != 0 || report.Summary.Excluded != 0 || report.Summary.Planned != 0 {
		t.Errorf("incomplete snapshot: %+v", report.Summary)
	}
}

func TestOriginal90MappingIdentities(t *testing.T) {
	data, err := os.ReadFile("testdata/original-90.txt")
	if err != nil {
		t.Fatal(err)
	}
	current := map[string][]string{}
	for _, r := range snapshotReport(t).Operations {
		current[r.Operation.OperationID] = []string{r.Operation.OperationID, r.Operation.Method, r.Operation.Path, string(r.MappingType), r.MCPName, r.ResourceURI, r.GrantPermission, r.Confirmation, string(r.Status)}
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		want := strings.Fields(line)
		if len(want) != 9 || seen[want[0]] {
			t.Fatalf("invalid baseline row: %q", line)
		}
		seen[want[0]] = true
		for i, value := range want {
			if value == "-" {
				want[i] = ""
			}
		}
		if got := current[want[0]]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s mapping identity changed:\n got %q\nwant %q", want[0], got, want)
		}
	}
	if len(seen) != 90 {
		t.Fatalf("original baseline has %d operations, want 90", len(seen))
	}
}

func TestLifecycleCanonicalMappings(t *testing.T) {
	for _, want := range []struct {
		id, method, path, name, confirmation string
		readOnly, destructive, idempotent    bool
	}{
		{"listOrganizationTailnets", "GET", "/organizations/{organization}/tailnets", "tailscale_list_organization_tailnets", "", true, false, true},
		{"createOrganizationTailnet", "POST", "/organizations/{organization}/tailnets", "tailscale_create_organization_tailnet", "createOrganizationTailnet", false, false, false},
		{"deleteTailnet", "DELETE", "/tailnet/{tailnet}", "tailscale_delete_tailnet", "deleteTailnet", false, true, true},
	} {
		t.Run(want.id, func(t *testing.T) {
			count := 0
			for _, mapping := range CurrentMappings() {
				if mapping.OperationID != want.id {
					continue
				}
				count++
				if mapping.Type != MappingTool || mapping.Name != want.name || mapping.URI != "" || mapping.GrantPermission != "tool:"+want.name || mapping.Confirmation != want.confirmation || mapping.ReadOnly != want.readOnly || mapping.Destructive != want.destructive || mapping.Idempotent != want.idempotent || !strings.Contains(mapping.Rationale, "Alpha") {
					t.Errorf("unexpected canonical mapping: %+v", mapping)
				}
			}
			if count != 1 {
				t.Fatalf("got %d lifecycle mappings, want exactly one tool", count)
			}
			found := false
			for _, r := range snapshotReport(t).Operations {
				if r.Operation.OperationID == want.id {
					found = true
					if r.Operation.Method != want.method || r.Operation.Path != want.path || r.Status != StatusImplemented {
						t.Errorf("unexpected lifecycle report record: %+v", r)
					}
				}
			}
			if !found {
				t.Fatal("lifecycle operation missing from snapshot")
			}
		})
	}
}

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
