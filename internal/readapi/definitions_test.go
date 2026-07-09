package readapi

import "testing"

func TestReadEndpointsAreUnique(t *testing.T) {
	operationIDs := map[string]bool{}
	toolNames := map[string]bool{}
	for _, endpoint := range ToolEndpoints() {
		if endpoint.OperationID == "" {
			t.Fatal("empty operation ID")
		}
		if operationIDs[endpoint.OperationID] {
			t.Fatalf("duplicate operation ID %q", endpoint.OperationID)
		}
		operationIDs[endpoint.OperationID] = true

		if endpoint.ToolName == "" {
			t.Fatalf("empty tool name for %q", endpoint.OperationID)
		}
		if toolNames[endpoint.ToolName] {
			t.Fatalf("duplicate tool name %q", endpoint.ToolName)
		}
		toolNames[endpoint.ToolName] = true
	}
}

func TestResourcesReferenceReadEndpoints(t *testing.T) {
	operationIDs := map[string]bool{}
	for _, endpoint := range ReadEndpoints() {
		operationIDs[endpoint.OperationID] = true
	}
	for _, resource := range Resources() {
		if !operationIDs[resource.OperationID] {
			t.Fatalf("resource %q references unknown operation %q", resource.URI, resource.OperationID)
		}
		if resource.Endpoint.OperationID != resource.OperationID {
			t.Fatalf("resource %q has mismatched endpoint %q", resource.URI, resource.Endpoint.OperationID)
		}
	}
	for _, resource := range ResourceTemplates() {
		if !operationIDs[resource.OperationID] {
			t.Fatalf("resource template %q references unknown operation %q", resource.URI, resource.OperationID)
		}
		if resource.Endpoint.OperationID != resource.OperationID {
			t.Fatalf("resource template %q has mismatched endpoint %q", resource.URI, resource.Endpoint.OperationID)
		}
	}
}
