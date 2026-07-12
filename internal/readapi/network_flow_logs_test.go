package readapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestNetworkFlowLogChunkUsesBoundedWindows(t *testing.T) {
	var queries []url.Values
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tailnet/example.com/logging/network" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		queries = append(queries, r.URL.Query())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"logs":[{"nodeId":"node-1"}]}`))
	}))
	defer api.Close()

	endpoint := networkFlowLogEndpoint(t)
	client := Client{Tailnet: "example.com", BaseURL: api.URL}
	start := "2026-07-12T12:00:00Z"
	end := "2026-07-12T12:12:00Z"
	first, err := client.networkFlowLogChunk(context.Background(), endpoint, map[string]any{"start": start, "end": end})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(first.Logs); got != `[{"nodeId":"node-1"}]` {
		t.Fatalf("logs = %s", got)
	}
	if got, want := first.Start.Format(time.RFC3339), start; got != want {
		t.Fatalf("first start = %q, want %q", got, want)
	}
	if got, want := first.End.Format(time.RFC3339), "2026-07-12T12:05:00Z"; got != want {
		t.Fatalf("first end = %q, want %q", got, want)
	}
	if first.NextCursor == nil {
		t.Fatal("first chunk did not include next cursor")
	}

	second, err := client.networkFlowLogChunk(context.Background(), endpoint, map[string]any{"cursor": *first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := second.Start.Format(time.RFC3339), "2026-07-12T12:05:00Z"; got != want {
		t.Fatalf("second start = %q, want %q", got, want)
	}
	if got, want := second.End.Format(time.RFC3339), "2026-07-12T12:10:00Z"; got != want {
		t.Fatalf("second end = %q, want %q", got, want)
	}
	if second.NextCursor == nil {
		t.Fatal("second chunk did not include next cursor")
	}

	third, err := client.networkFlowLogChunk(context.Background(), endpoint, map[string]any{"cursor": *second.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := third.End.Format(time.RFC3339), end; got != want {
		t.Fatalf("third end = %q, want %q", got, want)
	}
	if third.NextCursor != nil {
		t.Fatalf("final chunk cursor = %q, want nil", *third.NextCursor)
	}

	wantQueries := [][2]string{
		{"2026-07-12T12:00:00Z", "2026-07-12T12:05:00Z"},
		{"2026-07-12T12:05:00Z", "2026-07-12T12:10:00Z"},
		{"2026-07-12T12:10:00Z", "2026-07-12T12:12:00Z"},
	}
	if len(queries) != len(wantQueries) {
		t.Fatalf("request count = %d, want %d", len(queries), len(wantQueries))
	}
	for i, want := range wantQueries {
		if got := [2]string{queries[i].Get("start"), queries[i].Get("end")}; got != want {
			t.Fatalf("query %d = %#v, want %#v", i, got, want)
		}
	}
}

func TestNetworkFlowLogChunkReturnsSingleShortRange(t *testing.T) {
	var query url.Values
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		_, _ = w.Write([]byte(`{"logs":[]}`))
	}))
	defer api.Close()

	endpoint := networkFlowLogEndpoint(t)
	client := Client{Tailnet: "example.com", BaseURL: api.URL}
	chunk, err := client.networkFlowLogChunk(context.Background(), endpoint, map[string]any{"start": "2026-07-12T12:00:00Z", "end": "2026-07-12T12:03:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if chunk.NextCursor != nil {
		t.Fatalf("short range cursor = %q, want nil", *chunk.NextCursor)
	}
	if got, want := query.Get("end"), "2026-07-12T12:03:00Z"; got != want {
		t.Fatalf("query end = %q, want %q", got, want)
	}
}

func TestNetworkFlowLogRangeRejectsInvalidInput(t *testing.T) {
	tests := []map[string]any{
		{},
		{"start": "not-a-time", "end": "2026-07-12T12:00:00Z"},
		{"start": "2026-07-12T12:00:00Z", "end": "2026-07-12T12:00:00Z"},
		{"cursor": "not-a-cursor"},
		{"cursor": "not-a-cursor", "start": "2026-07-12T12:00:00Z"},
	}
	for _, args := range tests {
		if _, _, err := networkFlowLogRange(args); err == nil {
			t.Fatalf("networkFlowLogRange(%#v) error = nil", args)
		}
	}
}

func TestNetworkFlowLogToolChecksAccessBeforeValidation(t *testing.T) {
	mcpServer := server.NewMCPServer("test", "0.0.1")
	denied := errors.New("denied")
	checkedTool := ""
	RegisterTools(mcpServer, Client{}, func(_ context.Context, tool string) error {
		checkedTool = tool
		return denied
	})

	tool := mcpServer.GetTool("tailscale_list_network_flow_logs")
	if tool == nil {
		t.Fatal("network flow log tool was not registered")
	}
	assertToolAnnotations(t, tool.Tool.Name, tool.Tool.Annotations.ReadOnlyHint, tool.Tool.Annotations.DestructiveHint, tool.Tool.Annotations.IdempotentHint, ToolHints{ReadOnly: true, Idempotent: true})
	result, err := tool.Handler(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{"cursor": "invalid"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("denied tool call did not return an error result")
	}
	if checkedTool != "tailscale_list_network_flow_logs" {
		t.Fatalf("access check tool = %q", checkedTool)
	}
}

func TestNetworkFlowLogToolRejectsInvalidInputWithoutAPICall(t *testing.T) {
	apiCalls := 0
	api := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		apiCalls++
	}))
	defer api.Close()

	mcpServer := server.NewMCPServer("test", "0.0.1")
	RegisterTools(mcpServer, Client{Tailnet: "example.com", BaseURL: api.URL}, func(context.Context, string) error { return nil })
	tool := mcpServer.GetTool("tailscale_list_network_flow_logs")
	result, err := tool.Handler(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{"cursor": "invalid"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("invalid tool call did not return an error result")
	}
	if apiCalls != 0 {
		t.Fatalf("API calls = %d, want 0", apiCalls)
	}
}

func networkFlowLogEndpoint(t *testing.T) Endpoint {
	t.Helper()
	for _, endpoint := range ReadEndpoints() {
		if endpoint.OperationID == "listNetworkFlowLogs" {
			return endpoint
		}
	}
	t.Fatal("network flow log endpoint not found")
	return Endpoint{}
}
