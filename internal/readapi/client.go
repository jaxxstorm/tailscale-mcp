package readapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const defaultBaseURL = "https://api.tailscale.com/api/v2"

type Client struct {
	Tailnet    string
	APIKey     string
	BaseURL    string
	HTTPClient *http.Client
}

type APIError struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
}

func (e APIError) Error() string {
	return fmt.Sprintf("tailscale API error %d: %s", e.StatusCode, e.Message)
}

func (c Client) Do(ctx context.Context, endpoint Endpoint, args map[string]any) (json.RawMessage, error) {
	path, query, err := Expand(endpoint, c.Tailnet, args)
	if err != nil {
		return nil, err
	}

	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	reqURL := base + path
	if query != "" {
		reqURL += "?" + query
	}

	var body io.Reader
	if endpoint.Body {
		if raw, ok := args["body"]; ok {
			data, err := json.Marshal(raw)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal request body: %w", err)
			}
			body = bytes.NewReader(data)
		}
	}

	req, err := http.NewRequestWithContext(ctx, endpoint.Method, reqURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, SanitizeAPIError(resp.StatusCode, data)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return json.RawMessage(data), nil
}

func Expand(endpoint Endpoint, tailnet string, args map[string]any) (string, string, error) {
	path := strings.ReplaceAll(endpoint.Path, "{tailnet}", url.PathEscape(tailnet))
	values := url.Values{}

	for _, param := range endpoint.Parameters {
		value, ok := args[param.Name]
		if param.Required && (!ok || value == nil || fmt.Sprint(value) == "") {
			return "", "", fmt.Errorf("missing required parameter %q", param.Name)
		}
		if !ok || value == nil || fmt.Sprint(value) == "" {
			continue
		}

		switch param.Location {
		case PathParam:
			path = strings.ReplaceAll(path, "{"+param.Name+"}", url.PathEscape(fmt.Sprint(value)))
		case QueryParam:
			addQueryValue(values, param.Name, value)
		}
	}

	if strings.Contains(path, "{") {
		return "", "", fmt.Errorf("unexpanded path template %q", path)
	}
	return path, values.Encode(), nil
}

func addQueryValue(values url.Values, name string, value any) {
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			values.Add(name, fmt.Sprint(item))
		}
	case []string:
		for _, item := range v {
			values.Add(name, item)
		}
	default:
		values.Add(name, fmt.Sprint(value))
	}
}

func SanitizeAPIError(statusCode int, data []byte) APIError {
	message := strings.TrimSpace(string(data))
	var decoded struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(data, &decoded); err == nil {
		if decoded.Message != "" {
			message = decoded.Message
		} else if decoded.Error != "" {
			message = decoded.Error
		}
	}
	if message == "" {
		message = http.StatusText(statusCode)
	}
	if len(message) > 1000 {
		message = message[:1000] + "..."
	}
	return APIError{StatusCode: statusCode, Message: message}
}
