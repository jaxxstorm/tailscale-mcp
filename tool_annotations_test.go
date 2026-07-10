package main

import (
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"
)

func TestCoreToolsApplyReadOnlyAnnotations(t *testing.T) {
	logger = zap.NewNop()
	mcpServer := server.NewMCPServer("test", "0.0.1")
	registerCoreMCP(mcpServer, nil)

	for _, name := range []string{"get_device_info", "list_all_devices"} {
		t.Run(name, func(t *testing.T) {
			tool := mcpServer.GetTool(name)
			if tool == nil {
				t.Fatalf("tool %q not registered", name)
			}
			annotations := tool.Tool.Annotations
			if annotations.ReadOnlyHint == nil || !*annotations.ReadOnlyHint {
				t.Fatalf("%s readOnlyHint = %v, want true", name, annotationValue(annotations.ReadOnlyHint))
			}
			if annotations.DestructiveHint == nil || *annotations.DestructiveHint {
				t.Fatalf("%s destructiveHint = %v, want false", name, annotationValue(annotations.DestructiveHint))
			}
			if annotations.IdempotentHint == nil || !*annotations.IdempotentHint {
				t.Fatalf("%s idempotentHint = %v, want true", name, annotationValue(annotations.IdempotentHint))
			}
		})
	}
}

func annotationValue(value *bool) any {
	if value == nil {
		return nil
	}
	return *value
}
