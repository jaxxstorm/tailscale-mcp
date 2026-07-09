package main

import (
	"testing"
	"time"
)

func TestBuildSnapshotMetadata(t *testing.T) {
	schema := []byte(`openapi: 3.1.0
info:
  version: v2
paths:
  /devices:
    get: {}
    post: {}
  /devices/{id}:
    parameters: []
    get: {}
    delete: {}
`)

	got, err := buildSnapshotMetadata(schema, "https://example.test/openapi.yaml", "tools/coverage/tailscale-v2-openapi.yaml", time.Date(2026, time.July, 9, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build snapshot metadata: %v", err)
	}

	if got.OpenAPIVersion != "3.1.0" {
		t.Fatalf("unexpected openapi version: %q", got.OpenAPIVersion)
	}
	if got.APIVersion != "v2" {
		t.Fatalf("unexpected api version: %q", got.APIVersion)
	}
	if got.PathCount != 2 {
		t.Fatalf("unexpected path count: %d", got.PathCount)
	}
	if got.OperationCount != 4 {
		t.Fatalf("unexpected operation count: %d", got.OperationCount)
	}
	if got.SchemaFile != "tailscale-v2-openapi.yaml" {
		t.Fatalf("unexpected schema file: %q", got.SchemaFile)
	}
	if got.SHA256 == "" {
		t.Fatal("expected sha256")
	}
}
