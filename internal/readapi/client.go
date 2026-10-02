package readapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
)

const defaultBaseURL = "https://api.tailscale.com/api/v2"

type Client struct {
	Tailnet    string
	Token      string
	BaseURL    string
	HTTPClient *http.Client
}

type RawResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

type APIError struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
}

type lifecycleError struct {
	Operation  string `json:"operation"`
	StatusCode int    `json:"statusCode,omitempty"`
	Message    string `json:"message"`
}

func (e lifecycleError) Error() string {
	data, _ := json.Marshal(e)
	return string(data)
}

// Only recognized message fields are returned; raw bodies and transport errors
// can contain credentials and must never become lifecycle error output.
func lifecycleAPIError(operation string, status int, data []byte, token string) lifecycleError {
	message := http.StatusText(status)
	// Authentication may be injected by a transport that keeps its credential
	// private. Without that credential, upstream prose cannot be safely redacted.
	if token == "" {
		return lifecycleError{Operation: operation, StatusCode: status, Message: message}
	}
	var decoded map[string]any
	if json.Unmarshal(data, &decoded) == nil {
		if value, ok := decoded["message"].(string); ok && strings.TrimSpace(value) != "" {
			message = value
		} else if value, ok := decoded["error"].(string); ok && strings.TrimSpace(value) != "" {
			message = value
		}
	}
	if token != "" {
		message = strings.ReplaceAll(message, token, "[redacted]")
	}
	var redact func(any, bool)
	redact = func(value any, sensitive bool) {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				key = strings.ToLower(key)
				redact(child, sensitive || strings.Contains(key, "secret") || strings.Contains(key, "token") || key == "authorization")
			}
		case []any:
			for _, child := range value {
				redact(child, sensitive)
			}
		case string:
			if sensitive && value != "" {
				message = strings.ReplaceAll(message, value, "[redacted]")
			}
		}
	}
	redact(decoded, false)
	// Do not echo credential-bearing prose even when no separate secret field exists.
	lower := strings.ToLower(message)
	for _, marker := range []string{"authorization", "bearer", "secret", "token", "oauth"} {
		if strings.Contains(lower, marker) {
			message = http.StatusText(status)
			break
		}
	}
	if len(message) > 1000 {
		message = message[:1000] + "..."
	}
	return lifecycleError{Operation: operation, StatusCode: status, Message: message}
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
				if endpoint.isLifecycle() {
					return nil, lifecycleError{Operation: endpoint.OperationID, Message: "failed to marshal request body"}
				}
				return nil, fmt.Errorf("failed to marshal request body: %w", err)
			}
			body = bytes.NewReader(data)
		}
	}

	req, err := http.NewRequestWithContext(ctx, endpoint.Method, reqURL, body)
	if err != nil {
		if endpoint.isLifecycle() {
			return nil, lifecycleError{Operation: endpoint.OperationID, Message: "failed to construct API request"}
		}
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	if endpoint.isLifecycle() {
		copy := *hc
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		hc = &copy
	}
	resp, err := hc.Do(req)
	if err != nil {
		if endpoint.isLifecycle() {
			return nil, lifecycleError{Operation: endpoint.OperationID, Message: "API request failed; outcome may be unknown"}
		}
		return nil, err
	}
	defer resp.Body.Close()

	const maxResponseBytes = 4 << 20
	limit := int64(maxResponseBytes)
	if endpoint.isLifecycle() {
		limit++ // Distinguish a complete response from a truncated one.
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		if endpoint.isLifecycle() {
			return nil, lifecycleError{Operation: endpoint.OperationID, StatusCode: resp.StatusCode, Message: "failed to read API response; outcome may be unknown"}
		}
		return nil, err
	}
	if endpoint.isLifecycle() && len(data) > maxResponseBytes {
		return nil, lifecycleError{Operation: endpoint.OperationID, StatusCode: resp.StatusCode, Message: "API response exceeds size limit; outcome may be unknown"}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if endpoint.isLifecycle() {
			return nil, lifecycleAPIError(endpoint.OperationID, resp.StatusCode, data, c.Token)
		}
		return nil, SanitizeAPIError(resp.StatusCode, data)
	}
	if endpoint.isLifecycle() {
		valid := json.Valid(data)
		if endpoint.OperationID == "deleteTailnet" {
			valid = valid || len(bytes.TrimSpace(data)) == 0
		} else {
			// Listing and creation promise JSON objects, not empty acknowledgements.
			var object map[string]json.RawMessage
			valid = json.Unmarshal(data, &object) == nil && len(object) > 0
		}
		if !valid {
			return nil, lifecycleError{Operation: endpoint.OperationID, StatusCode: resp.StatusCode, Message: "invalid API response; outcome may be unknown"}
		}
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return json.RawMessage(data), nil
}

func (c Client) DoRaw(ctx context.Context, endpoint Endpoint, args map[string]any, body []byte, headers map[string]string) (RawResponse, error) {
	path, query, err := Expand(endpoint, c.Tailnet, args)
	if err != nil {
		return RawResponse{}, err
	}

	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	reqURL := base + path
	if query != "" {
		reqURL += "?" + query
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, reqURL, reader)
	if err != nil {
		return RawResponse{}, err
	}
	for key, value := range headers {
		if value != "" {
			req.Header.Set(key, value)
		}
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return RawResponse{}, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return RawResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return RawResponse{}, SanitizeAPIError(resp.StatusCode, data)
	}
	return RawResponse{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: data}, nil
}

func Expand(endpoint Endpoint, tailnet string, args map[string]any) (string, string, error) {
	if endpoint.OperationID == "deleteTailnet" {
		target, ok := args["tailnet"].(string)
		if !ok || strings.TrimSpace(tailnet) == "" || tailnet == "-" || target != tailnet {
			return "", "", fmt.Errorf("tailnet must exactly match an explicitly configured target other than -")
		}
	}
	if len(endpoint.RequiredBodyStrings) > 0 {
		body, ok := args["body"].(map[string]any)
		if !ok || body == nil {
			return "", "", fmt.Errorf("body must be an object")
		}
		for _, name := range endpoint.RequiredBodyStrings {
			value, ok := body[name].(string)
			if !ok || strings.TrimSpace(value) == "" {
				return "", "", fmt.Errorf("body.%s must be a nonblank string", name)
			}
		}
	}
	path := strings.ReplaceAll(endpoint.Path, "{tailnet}", url.PathEscape(tailnet))
	values := url.Values{}

	for _, param := range endpoint.Parameters {
		value, ok := args[param.Name]
		if ok || param.Required {
			if param.StrictString {
				text, valid := value.(string)
				if !valid || (param.Required && strings.TrimSpace(text) == "") {
					return "", "", fmt.Errorf("%s must be a string and must not be blank when required", param.Name)
				}
			}
			if bounds := param.IntegerBounds; bounds != nil {
				var number float64
				switch n := value.(type) {
				case float64:
					number = n
				case int:
					number = float64(n)
				case int64:
					number = float64(n)
				case json.Number:
					var err error
					number, err = n.Float64()
					if err != nil {
						return "", "", fmt.Errorf("%s must be an integer", param.Name)
					}
				default:
					return "", "", fmt.Errorf("%s must be an integer", param.Name)
				}
				if math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number || number < float64(bounds.Minimum) || number > float64(bounds.Maximum) {
					return "", "", fmt.Errorf("%s must be an integer from %d through %d", param.Name, bounds.Minimum, bounds.Maximum)
				}
				value = int(number)
			}
		}
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
