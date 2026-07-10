package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestStreamableHTTPTransportConstants(t *testing.T) {
	if streamableHTTPTransportName != "Streamable HTTP" {
		t.Fatalf("unexpected transport name %q", streamableHTTPTransportName)
	}
	if mcpEndpointPath != "/mcp" {
		t.Fatalf("unexpected MCP endpoint path %q", mcpEndpointPath)
	}
}

func TestAllowOriginMiddlewareRejectsForbiddenOriginBeforeNext(t *testing.T) {
	logger = zap.NewNop()
	called := false
	handler := allowOriginMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodPost, "http://ts-mcp.example/mcp", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("next handler was called for forbidden origin")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
}

func TestAllowOriginMiddlewareAllowsSameHostOrigin(t *testing.T) {
	logger = zap.NewNop()
	called := false
	handler := allowOriginMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "http://ts-mcp.example/mcp", nil)
	req.Header.Set("Origin", "http://ts-mcp.example")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("next handler was not called for same-host origin")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}
}
