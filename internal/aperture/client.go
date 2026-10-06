// Package aperture exposes the bounded, identity-aware Aperture API tools.
package aperture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tailscale/hujson"
)

const maxResponseBytes = 16 << 20

// Client's zero value supports offline registration but cannot make requests.
type Client struct {
	base *url.URL
	http *http.Client
}

// CloseIdleConnections releases the transport owned by this client at shutdown.
func (c Client) CloseIdleConnections() {
	if c.http != nil {
		c.http.CloseIdleConnections()
	}
}

// ValidateBaseURL validates operator configuration without contacting the upstream.
// Errors intentionally do not include the URL, which might contain credentials.
func ValidateBaseURL(baseURL string) error {
	u, err := url.Parse(baseURL)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(baseURL, "#") {
		return errors.New("Aperture base URL must be an absolute HTTP(S) URL without userinfo, query, or fragment")
	}
	return nil
}

// NewClient requires an explicit transport. Production supplies a tsnet dialer.
// A supplied *http.Transport is cloned to disable proxies and insecure TLS.
func NewClient(baseURL string, transport http.RoundTripper) (Client, error) {
	if err := ValidateBaseURL(baseURL); err != nil {
		return Client{}, err
	}
	if transport == nil {
		return Client{}, errors.New("Aperture requires an identity-aware transport")
	}
	if t, ok := transport.(*http.Transport); ok {
		if t == nil {
			return Client{}, errors.New("Aperture requires an identity-aware transport")
		}
		t = t.Clone()
		t.Proxy = nil
		if t.TLSClientConfig != nil {
			t.TLSClientConfig.InsecureSkipVerify = false
		}
		transport = t
	}
	u, _ := url.Parse(baseURL)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = strings.TrimRight(u.RawPath, "/")
	return Client{base: u, http: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

type toolError struct {
	Status  int    `json:"status,omitempty"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

func (e *toolError) Error() string { return e.Message }

func failure(kind, message string) *toolError { return &toolError{Kind: kind, Message: message} }

func (c Client) call(ctx context.Context, op Operation, args map[string]any) (any, error) {
	path := op.Path
	var config, validator string
	for _, name := range requiredInputs(op.ToolName) {
		v, ok := args[name].(string)
		if !ok || strings.TrimSpace(v) == "" {
			return nil, failure("input", name+" must be a nonblank string")
		}
	}
	config, _ = args["config"].(string)
	if op.ToolName == "aperture_set_config" {
		if args["confirm"] != op.ToolName {
			return nil, failure("input", "confirm must equal aperture_set_config")
		}
		validator = args["if_match"].(string)
		if !concreteETag(validator) {
			return nil, failure("input", "if_match must be a single concrete strong ETag from aperture_get_config")
		}
	}
	pricing := op.Group == "aperture-pricing"
	if pricing {
		if raw, exists := args["if_none_match"]; exists {
			var ok bool
			validator, ok = raw.(string)
			if !ok || strings.TrimSpace(validator) == "" || strings.ContainsAny(validator, "\r\n\x00") {
				return nil, failure("input", "if_none_match must be a nonblank HTTP header string")
			}
		}
	}
	if op.ToolName == "aperture_get_model_pricing" {
		parts := strings.Split(args["model"].(string), "/")
		for i, part := range parts {
			if strings.TrimSpace(part) == "" || part == "." || part == ".." {
				return nil, failure("input", "model must not contain empty or dot path segments")
			}
			parts[i] = url.PathEscape(part)
		}
		path = "/pricing/" + strings.Join(parts, "/")
	}
	if c.base == nil || c.http == nil {
		return nil, failure("unavailable", "Aperture client is not configured")
	}
	u := *c.base
	u.RawPath = c.base.EscapedPath() + path
	u.Path, _ = url.PathUnescape(u.RawPath)
	var body io.Reader
	if config != "" {
		data, _ := json.Marshal(map[string]string{"config": config})
		// Do not provide GetBody: conditional writes must not be replayed by Transport.
		body = io.NopCloser(bytes.NewReader(data))
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, u.String(), body)
	if err != nil {
		return nil, failure("input", "Unable to construct Aperture request")
	}
	req.Header.Set("Accept", "application/json")
	if config != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if validator != "" {
		header := "If-Match"
		if pricing {
			header = "If-None-Match"
		}
		req.Header.Set(header, validator)
	}
	uncertain := func(message string) error {
		if !op.ReadOnly {
			message += "; write outcome is uncertain: inspect configuration before deliberately retrying"
		}
		return failure("upstream", message)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, uncertain("Aperture request failed or was canceled")
	}
	defer resp.Body.Close()
	etag := resp.Header.Get("ETag")
	if pricing && resp.StatusCode == http.StatusNotModified {
		if etag == "" {
			etag = validator
		}
		return map[string]any{"etag": etag, "not_modified": true}, nil
	}
	if resp.StatusCode != http.StatusOK {
		message := "Aperture rejected the request"
		switch resp.StatusCode {
		case 403:
			message = "Aperture requires the MCP node to have upstream admin permission"
			if pricing {
				message = "Aperture requires explicit upstream read_pricing: true; admin alone is insufficient"
			}
		case 412:
			message = "Configuration conflict: read the current configuration and deliberately retry with its ETag"
		case 422:
			message = "Aperture validation failed; inspect the submitted fields without disclosing provider secrets"
		default:
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				message = "Aperture redirects are not allowed"
			}
			if resp.StatusCode >= 500 {
				message = "Aperture upstream service failed"
				if !op.ReadOnly {
					message += "; write outcome is uncertain: inspect configuration before retrying"
				}
			}
		}
		return nil, &toolError{Status: resp.StatusCode, Kind: "http", Message: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, message)}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, uncertain("Unable to read complete Aperture response")
	}
	if len(data) > maxResponseBytes {
		return nil, uncertain("Aperture response exceeds 16 MiB; use exact-model pricing for a smaller catalog")
	}
	bad := func() (any, error) { return nil, uncertain("Malformed or unexpected Aperture response") }
	if pricing {
		data, err = hujson.Standardize(data)
		if err != nil {
			return bad()
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(data, &obj) != nil || obj == nil {
			return bad()
		}
		var currency string
		var bases []*string
		if json.Unmarshal(obj["currency"], &currency) != nil || string(obj["currency"]) == "null" || json.Unmarshal(obj["cost_bases"], &bases) != nil {
			return bad()
		}
		for _, basis := range bases {
			if basis == nil {
				return bad()
			}
		}
		for _, field := range []string{"units", "models", "configured_adjustments"} {
			var value map[string]json.RawMessage
			if json.Unmarshal(obj[field], &value) != nil || value == nil {
				return bad()
			}
		}
		if !validPricing(data) {
			return bad()
		}
		return map[string]any{"data": json.RawMessage(data), "etag": etag, "not_modified": false}, nil
	}
	if op.ToolName == "aperture_validate_config" {
		var result struct {
			Valid  *bool           `json:"valid"`
			Errors json.RawMessage `json:"errors"`
		}
		if json.Unmarshal(data, &result) != nil || result.Valid == nil || len(result.Errors) == 0 {
			return bad()
		}
		var diagnostics []*string
		if json.Unmarshal(result.Errors, &diagnostics) != nil {
			return bad()
		}
		for _, diagnostic := range diagnostics {
			if diagnostic == nil {
				return bad()
			}
		}
		// Arbitrary diagnostic strings cannot be proved secret-free, even when
		// they do not literally match the submitted (possibly escaped) config.
		safe := []string{}
		if len(diagnostics) > 0 || !*result.Valid {
			safe = append(safe, "Configuration validation failed; inspect configuration fields and provider settings locally")
		}
		return map[string]any{"valid": *result.Valid, "errors": safe}, nil
	}
	var result struct {
		Config *string `json:"config"`
	}
	if json.Unmarshal(data, &result) != nil || result.Config == nil || strings.TrimSpace(*result.Config) == "" {
		return bad()
	}
	return map[string]any{"config": *result.Config, "etag": etag}, nil
}

func concreteETag(s string) bool {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	for _, b := range []byte(s[1 : len(s)-1]) {
		if b < 0x21 || b == '"' || b == 0x7f {
			return false
		}
	}
	return true
}
