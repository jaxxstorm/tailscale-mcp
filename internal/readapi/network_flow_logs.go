package readapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const networkFlowLogChunkDuration = 5 * time.Minute

type networkFlowLogCursor struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type networkFlowLogChunk struct {
	Logs       json.RawMessage `json:"logs"`
	Start      time.Time       `json:"start"`
	End        time.Time       `json:"end"`
	NextCursor *string         `json:"nextCursor,omitempty"`
}

func registerNetworkFlowLogTool(mcpServer *server.MCPServer, client Client, check AccessChecker, endpoint Endpoint) {
	hints := endpoint.ToolHints()
	mcpServer.AddTool(mcp.NewTool(endpoint.ToolName,
		mcp.WithDescription("List network flow logs in five-minute chronological chunks. Provide start and end for the first chunk, then pass nextCursor as cursor to continue."),
		mcp.WithString("start", mcp.Description("RFC3339 start time for the first chunk")),
		mcp.WithString("end", mcp.Description("RFC3339 end time for the requested range")),
		mcp.WithString("cursor", mcp.Description("Continuation cursor from a previous response")),
		mcp.WithReadOnlyHintAnnotation(hints.ReadOnly),
		mcp.WithDestructiveHintAnnotation(hints.Destructive),
		mcp.WithIdempotentHintAnnotation(hints.Idempotent),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		chunk, err := withAccess(ctx, endpoint.ToolName, check, func() (networkFlowLogChunk, error) {
			return client.networkFlowLogChunk(ctx, endpoint, req.GetArguments())
		})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultStructuredOnly(chunk), nil
	})
}

func (c Client) networkFlowLogChunk(ctx context.Context, endpoint Endpoint, args map[string]any) (networkFlowLogChunk, error) {
	start, end, err := networkFlowLogRange(args)
	if err != nil {
		return networkFlowLogChunk{}, err
	}

	chunkEnd := start.Add(networkFlowLogChunkDuration)
	if chunkEnd.After(end) {
		chunkEnd = end
	}
	data, err := c.Do(ctx, endpoint, map[string]any{
		"start": start.Format(time.RFC3339Nano),
		"end":   chunkEnd.Format(time.RFC3339Nano),
	})
	if err != nil {
		return networkFlowLogChunk{}, err
	}

	var response struct {
		Logs json.RawMessage `json:"logs"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return networkFlowLogChunk{}, fmt.Errorf("invalid network flow log response: %w", err)
	}

	chunk := networkFlowLogChunk{Logs: response.Logs, Start: start, End: chunkEnd}
	if chunkEnd.Before(end) {
		cursor, err := encodeNetworkFlowLogCursor(networkFlowLogCursor{Start: chunkEnd, End: end})
		if err != nil {
			return networkFlowLogChunk{}, err
		}
		chunk.NextCursor = &cursor
	}
	return chunk, nil
}

func networkFlowLogRange(args map[string]any) (time.Time, time.Time, error) {
	cursor := argumentString(args, "cursor")
	start := argumentString(args, "start")
	end := argumentString(args, "end")
	if cursor != "" {
		if start != "" || end != "" {
			return time.Time{}, time.Time{}, fmt.Errorf("cursor cannot be combined with start or end")
		}
		decoded, err := decodeNetworkFlowLogCursor(cursor)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		return decoded.Start, decoded.End, nil
	}
	if start == "" || end == "" {
		return time.Time{}, time.Time{}, fmt.Errorf("start and end are required when cursor is not provided")
	}

	startTime, err := time.Parse(time.RFC3339, start)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid start timestamp: %w", err)
	}
	endTime, err := time.Parse(time.RFC3339, end)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid end timestamp: %w", err)
	}
	if !startTime.Before(endTime) {
		return time.Time{}, time.Time{}, fmt.Errorf("end must be after start")
	}
	return startTime, endTime, nil
}

func encodeNetworkFlowLogCursor(cursor networkFlowLogCursor) (string, error) {
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", fmt.Errorf("encode network flow log cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeNetworkFlowLogCursor(encoded string) (networkFlowLogCursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return networkFlowLogCursor{}, fmt.Errorf("invalid network flow log cursor")
	}
	var cursor networkFlowLogCursor
	if err := json.Unmarshal(data, &cursor); err != nil || cursor.Start.IsZero() || cursor.End.IsZero() || !cursor.Start.Before(cursor.End) {
		return networkFlowLogCursor{}, fmt.Errorf("invalid network flow log cursor")
	}
	return cursor, nil
}

func argumentString(args map[string]any, name string) string {
	if args == nil || args[name] == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(args[name]))
}
