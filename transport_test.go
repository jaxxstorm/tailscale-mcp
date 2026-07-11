package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"tailscale.com/hostinfo"
)

func TestStreamableHTTPTransportConstants(t *testing.T) {
	if mcpServerName != "ts-mcp" {
		t.Fatalf("unexpected MCP server name %q", mcpServerName)
	}
	if streamableHTTPTransportName != "Streamable HTTP" {
		t.Fatalf("unexpected transport name %q", streamableHTTPTransportName)
	}
	if mcpEndpointPath != "/mcp" {
		t.Fatalf("unexpected MCP endpoint path %q", mcpEndpointPath)
	}
}

func TestTSNetStateDirUsesHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     string
	}{
		{name: "default hostname", hostname: "ts-mcp", want: "tsnet-ts-mcp"},
		{name: "custom hostname", hostname: "ops-mcp", want: "tsnet-ops-mcp"},
		{name: "empty hostname fallback", hostname: " ", want: "tsnet-ts-mcp"},
		{name: "sanitized hostname", hostname: "Ops MCP/Prod", want: "tsnet-ops-mcp-prod"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tsnetStateDir(tt.hostname); got != tt.want {
				t.Fatalf("tsnetStateDir(%q) = %q, want %q", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestNewTSNetServerPreservesStartupConfiguration(t *testing.T) {
	logger = zap.NewNop()
	credential := TailscaleCredential{Kind: CredentialOAuth, ClientID: "cid", ClientSecret: "secret"}
	tags := []string{"tag:mcp-server"}

	tsServer := newTSNetServer("ops-mcp", tags, credential, false)

	if tsServer.Dir != "tsnet-ops-mcp" {
		t.Fatalf("Dir = %q, want %q", tsServer.Dir, "tsnet-ops-mcp")
	}
	if tsServer.Hostname != "ops-mcp" {
		t.Fatalf("Hostname = %q, want %q", tsServer.Hostname, "ops-mcp")
	}
	if len(tsServer.AdvertiseTags) != 1 || tsServer.AdvertiseTags[0] != "tag:mcp-server" {
		t.Fatalf("AdvertiseTags = %#v, want %#v", tsServer.AdvertiseTags, tags)
	}
	if tsServer.ClientSecret != "secret" || tsServer.AuthKey != "" {
		t.Fatalf("unexpected credential configuration: %#v", tsServer)
	}
	if tsServer.UserLogf == nil {
		t.Fatal("UserLogf is nil, want application logger")
	}
	if tsServer.Logf != nil {
		t.Fatal("Logf is configured without debug enabled")
	}
}

func TestNewTSNetServerConfiguresDebugLogf(t *testing.T) {
	logger = zap.NewNop()
	tsServer := newTSNetServer("ops-mcp", nil, TailscaleCredential{}, true)

	if tsServer.UserLogf == nil {
		t.Fatal("UserLogf is nil, want application logger")
	}
	if tsServer.Logf == nil {
		t.Fatal("Logf is nil with debug enabled")
	}
}

func TestTSNetZapLogfWritesFormattedMessageWithComponent(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	logf := tsnetZapLogf(zap.New(core), zapcore.InfoLevel)

	logf("state path %s", "tsnet-ts-mcp/tailscaled.state")

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("logged %d entries, want 1", len(entries))
	}
	if entries[0].Level != zapcore.InfoLevel {
		t.Fatalf("level = %s, want %s", entries[0].Level, zapcore.InfoLevel)
	}
	if entries[0].Message != "state path tsnet-ts-mcp/tailscaled.state" {
		t.Fatalf("message = %q", entries[0].Message)
	}
	fields := entries[0].ContextMap()
	if fields["component"] != "tsnet" {
		t.Fatalf("component = %#v, want tsnet", fields["component"])
	}
}

func TestTSNetZapLogfRespectsLogLevel(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	logf := tsnetZapLogf(zap.New(core), zapcore.DebugLevel)

	logf("debug-only")

	if logs.Len() != 0 {
		t.Fatalf("logged %d entries, want 0", logs.Len())
	}
}

func TestRegisterTSNetBuildInfo(t *testing.T) {
	registerTSNetBuildInfo()

	hi := hostinfo.New()
	if hi.App != mcpServerName {
		t.Fatalf("Hostinfo App = %q, want %q", hi.App, mcpServerName)
	}
	if hi.IPNVersion != buildVersion {
		t.Fatalf("Hostinfo IPNVersion = %q, want %q", hi.IPNVersion, buildVersion)
	}
	if hi.OS != mcpServerName {
		t.Fatalf("Hostinfo OS = %q, want %q", hi.OS, mcpServerName)
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
