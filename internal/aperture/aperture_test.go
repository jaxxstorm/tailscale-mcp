package aperture

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jaxxstorm/tailscale-mcp/internal/toolmeta"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Etag": {`"version"`}}, Body: io.NopCloser(strings.NewReader(body))}
}
func operation(name string) Operation {
	for _, op := range Operations() {
		if op.ToolName == "aperture_"+name {
			return op
		}
	}
	panic(name)
}
func newTestClient(t *testing.T, rt roundTrip) Client {
	t.Helper()
	c, err := NewClient("http://ai/aperture/", rt)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const pricingBody = `{// comment
 "currency":"USD", "units":{"input":{"quantity":1000000,"basis":"tokens"}}, "cost_bases":["retail"], "models":{}, "configured_adjustments":{"providers":{}},
}`

func TestURLAndTransport(t *testing.T) {
	for _, raw := range []string{"", "ai/aperture", "ftp://ai", "http:///aperture", "http://user:secret@ai", "http://ai?x=secret", "http://ai?", "http://ai#", "http://ai#secret", "http://ai:bad"} {
		if ValidateBaseURL(raw) == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"http://ai/aperture", "http://ai/aperture/", "https://ai/prefix/aperture///"} {
		if err := ValidateBaseURL(raw); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewClient("http://ai", nil); err == nil {
		t.Fatal("nil transport accepted")
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	c, err := NewClient("https://ai/aperture/", transport)
	if err != nil {
		t.Fatal(err)
	}
	got := c.http.Transport.(*http.Transport)
	if got.Proxy != nil || got.TLSClientConfig.InsecureSkipVerify || !transport.TLSClientConfig.InsecureSkipVerify || c.http.Timeout != 30*time.Second {
		t.Fatal("unsafe transport settings or modified caller transport")
	}
	if c.base.Path != "/aperture" {
		t.Fatal(c.base)
	}
}

func TestConfigRequests(t *testing.T) {
	for _, name := range []string{"get_config", "validate_config", "set_config"} {
		t.Run(name, func(t *testing.T) {
			op := operation(name)
			calls := 0
			c := newTestClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != op.Method || r.URL.Path != "/aperture"+op.Path {
					t.Fatalf("request %s %s", r.Method, r.URL)
				}
				for _, h := range []string{"Authorization", "Cookie", "Tailscale-User-Login", "X-Forwarded-For"} {
					if r.Header.Get(h) != "" {
						t.Fatalf("unexpected header %s", h)
					}
				}
				if name != "get_config" {
					var body map[string]string
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 || body["config"] != "{ /* secret */ }" {
						t.Fatalf("body: %v %v", body, err)
					}
				}
				if name == "set_config" && (r.Header.Get("If-Match") != `"old"` || r.GetBody != nil) {
					t.Fatal("missing guard or replayable write")
				}
				if name == "validate_config" {
					return response(200, `{"valid":false,"errors":["secret in provider: secret"]}`), nil
				}
				return response(200, `{"config":"{ /* redacted */ }"}`), nil
			})
			result, err := c.call(context.Background(), op, map[string]any{"config": "{ /* secret */ }", "confirm": "aperture_set_config", "if_match": `"old"`})
			if err != nil || calls != 1 {
				t.Fatalf("%v calls=%d", err, calls)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), "secret") {
				t.Fatal(string(encoded))
			}
			if name != "validate_config" && (!strings.Contains(string(encoded), "redacted") || result.(map[string]any)["etag"] != `"version"`) {
				t.Fatal(result)
			}
		})
	}
}

func TestResponseETags(t *testing.T) {
	for _, name := range []string{"get_config", "set_config", "get_pricing", "get_model_pricing"} {
		for _, tc := range []struct {
			name        string
			tags        []string
			valid, weak bool
		}{
			{name: "missing"},
			{name: "empty", tags: []string{""}},
			{name: "unquoted", tags: []string{"secret"}},
			{name: "wildcard", tags: []string{"*"}},
			{name: "list", tags: []string{`"one", "two"`}},
			{name: "duplicate", tags: []string{`"one"`, `"two"`}},
			{name: "control", tags: []string{"\"secret\x7f\""}},
			{name: "strong", tags: []string{`"version"`}, valid: true},
			{name: "empty opaque value", tags: []string{`""`}, valid: true},
			{name: "weak", tags: []string{`W/"version"`}, valid: true, weak: true},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				op := operation(name)
				calls := 0
				c := newTestClient(t, func(*http.Request) (*http.Response, error) {
					calls++
					body := `{"config":"{}"}`
					if op.Group == "aperture-pricing" {
						body = pricingBody
					}
					r := response(200, body)
					r.Header.Del("ETag")
					for _, tag := range tc.tags {
						r.Header.Add("ETag", tag)
					}
					return r, nil
				})
				result, err := c.call(context.Background(), op, map[string]any{"config": "{}", "confirm": "aperture_set_config", "if_match": `"old"`, "model": "provider/model"})
				valid := tc.valid && (!tc.weak || op.Group == "aperture-pricing")
				if calls != 1 || (err == nil) != valid {
					t.Fatalf("calls=%d result=%v error=%v", calls, result, err)
				}
				if valid {
					if result.(map[string]any)["etag"] != tc.tags[0] {
						t.Fatal("ETag was not preserved")
					}
				} else if result != nil || !strings.Contains(err.Error(), "Malformed") || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "uncertain") != (name == "set_config") {
					t.Fatalf("unexpected failure: result=%v error=%v", result, err)
				}
			})
		}
	}
	// Validation does not use a version validator.
	c := newTestClient(t, func(*http.Request) (*http.Response, error) {
		r := response(200, `{"valid":true,"errors":[]}`)
		r.Header.Del("ETag")
		return r, nil
	})
	if _, err := c.call(context.Background(), operation("validate_config"), map[string]any{"config": "{}"}); err != nil {
		t.Fatal(err)
	}
}

func TestNotModifiedETags(t *testing.T) {
	for _, name := range []string{"get_pricing", "get_model_pricing"} {
		for _, tc := range []struct {
			name, tag, prior string
			valid            bool
		}{
			{"strong", `"new"`, `"old"`, true},
			{"weak", `W/"new"`, `"old"`, true},
			{"fallback", "", `"old"`, true},
			{"weak fallback", "", `W/"old"`, true},
			{"missing", "", "", false},
			{"malformed", "secret", `"old"`, false},
			{"wildcard fallback", "", "*", false},
			{"list fallback", "", `"one", "two"`, false},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				c := newTestClient(t, func(*http.Request) (*http.Response, error) {
					r := response(304, "")
					r.Header.Del("ETag")
					if tc.tag != "" {
						r.Header.Set("ETag", tc.tag)
					}
					return r, nil
				})
				args := map[string]any{"model": "provider/model"}
				if tc.prior != "" {
					args["if_none_match"] = tc.prior
				}
				result, err := c.call(context.Background(), operation(name), args)
				if (err == nil) != tc.valid {
					t.Fatalf("result=%v error=%v", result, err)
				}
				if tc.valid {
					want := tc.tag
					if want == "" {
						want = tc.prior
					}
					if result.(map[string]any)["etag"] != want {
						t.Fatal(result)
					}
				}
			})
		}
	}
}

func TestInputsRejectedOffline(t *testing.T) {
	c := newTestClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected upstream access"); return nil, nil })
	for _, v := range []any{nil, 42, "", " \n"} {
		for _, name := range []string{"validate_config", "set_config", "get_model_pricing"} {
			_, err := c.call(context.Background(), operation(name), map[string]any{"config": v, "model": v})
			if err == nil {
				t.Fatalf("accepted %s %v", name, v)
			}
		}
	}
	for _, tag := range []any{nil, 1, "", "*", "abc", `W/"weak"`, `"one", "two"`, "\"bad\n\""} {
		_, err := c.call(context.Background(), operation("set_config"), map[string]any{"config": "{}", "confirm": "aperture_set_config", "if_match": tag})
		if err == nil {
			t.Fatalf("accepted ETag %v", tag)
		}
	}
	for _, confirm := range []any{nil, 1, "", "wrong"} {
		_, err := c.call(context.Background(), operation("set_config"), map[string]any{"config": "{}", "confirm": confirm, "if_match": `"ok"`})
		if err == nil {
			t.Fatalf("accepted confirmation %v", confirm)
		}
	}
	for _, model := range []string{"/model", "model/", "a//b", "a/./b", "a/../b", ".", ".."} {
		if _, err := c.call(context.Background(), operation("get_model_pricing"), map[string]any{"model": model}); err == nil {
			t.Fatal(model)
		}
	}
	for _, validator := range []any{nil, 1, "", "x\r\nSecret: value"} {
		if _, err := c.call(context.Background(), operation("get_pricing"), map[string]any{"if_none_match": validator}); err == nil {
			t.Fatal(validator)
		}
	}
}

func TestPricing(t *testing.T) {
	for _, model := range []string{"", "provider/model", "provider/model?#%2F &"} {
		for _, status := range []int{200, 304} {
			t.Run(model+http.StatusText(status), func(t *testing.T) {
				c := newTestClient(t, func(r *http.Request) (*http.Response, error) {
					want := "/aperture/pricing"
					if model != "" {
						want += "/" + model
					}
					if r.URL.Path != want || r.URL.RawQuery != "" || r.URL.Fragment != "" || r.Header.Get("If-None-Match") != `"prior"` {
						t.Fatal(r.URL, r.Header)
					}
					if strings.Contains(model, "?") && !strings.Contains(r.URL.EscapedPath(), "%3F%23%252F") {
						t.Fatal(r.URL.EscapedPath())
					}
					resp := response(status, pricingBody)
					if status == 304 {
						resp.Header.Del("ETag")
						resp.Body = io.NopCloser(strings.NewReader(""))
					}
					return resp, nil
				})
				op := operation("get_pricing")
				if model != "" {
					op = operation("get_model_pricing")
				}
				data, err := c.call(context.Background(), op, map[string]any{"model": model, "if_none_match": `"prior"`})
				if err != nil {
					t.Fatal(err)
				}
				got := data.(map[string]any)
				if got["not_modified"] != (status == 304) {
					t.Fatal(got)
				}
				if status == 304 {
					if got["etag"] != `"prior"` || got["data"] != nil {
						t.Fatal(got)
					}
					return
				}
				encoded, _ := json.Marshal(data)
				for _, want := range []string{`"quantity":1000000`, `"basis":"tokens"`, `"models":{}`, `"cost_bases":["retail"]`, `"configured_adjustments"`} {
					if !strings.Contains(string(encoded), want) {
						t.Fatal(string(encoded))
					}
				}
			})
		}
	}
}

func TestHTTPFailures(t *testing.T) {
	for _, status := range []int{302, 403, 412, 422, 500, 503} {
		for _, name := range []string{"set_config", "get_pricing"} {
			calls := 0
			c := newTestClient(t, func(*http.Request) (*http.Response, error) {
				calls++
				r := response(status, `{"detail":"supersecret","errors":[{"value":"supersecret","location":"supersecret"}]}`)
				r.Header.Set("Location", "http://elsewhere/secret")
				return r, nil
			})
			_, err := c.call(context.Background(), operation(name), map[string]any{"config": "supersecret", "confirm": "aperture_set_config", "if_match": `"old"`})
			var detail *toolError
			if !errors.As(err, &detail) || detail.Status != status || calls != 1 || strings.Contains(err.Error(), "supersecret") {
				t.Fatalf("status %d: %v calls=%d", status, err, calls)
			}
			if status == 403 && name == "get_pricing" && !strings.Contains(err.Error(), "read_pricing") {
				t.Fatal(err)
			}
		}
	}
}

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errors.New("supersecret") }
func (brokenBody) Close() error             { return nil }

func TestBadResponses(t *testing.T) {
	for _, name := range []string{"get_config", "validate_config", "set_config", "get_pricing"} {
		for _, body := range []string{"", "{", "null", "{}", `{"config":42,"valid":"yes"}`, strings.Repeat("x", maxResponseBytes+1)} {
			c := newTestClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
			_, err := c.call(context.Background(), operation(name), map[string]any{"config": "{}", "confirm": "aperture_set_config", "if_match": `"old"`})
			if err == nil {
				t.Fatalf("accepted malformed %s", name)
			}
		}
	}
	c := newTestClient(t, func(*http.Request) (*http.Response, error) {
		r := response(200, "")
		r.Body = brokenBody{}
		return r, nil
	})
	_, err := c.call(context.Background(), operation("set_config"), map[string]any{"config": "{}", "confirm": "aperture_set_config", "if_match": `"old"`})
	if err == nil || !strings.Contains(err.Error(), "uncertain") || strings.Contains(err.Error(), "supersecret") {
		t.Fatal(err)
	}
}

func TestCancellationAndTimeout(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		calls := 0
		c := newTestClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			<-r.Context().Done()
			return nil, errors.New("supersecret")
		})
		ctx, cancel := context.WithCancel(context.Background())
		if timeout {
			c.http.Timeout = time.Millisecond
		} else {
			cancel()
		}
		_, err := c.call(ctx, operation("set_config"), map[string]any{"config": "supersecret", "confirm": "aperture_set_config", "if_match": `"old"`})
		cancel()
		if err == nil || !strings.Contains(err.Error(), "uncertain") || strings.Contains(err.Error(), "supersecret") || calls != 1 {
			t.Fatalf("%v calls=%d", err, calls)
		}
	}
}

func TestRegistrationAndGuards(t *testing.T) {
	s := server.NewMCPServer("aperture", "test")
	RegisterTools(s, Client{}, nil)
	catalog, err := toolmeta.New(ToolMetadata())
	if err != nil {
		t.Fatal(err)
	}
	if err = catalog.Validate(s.ListTools()); err != nil {
		t.Fatal(err)
	}
	for name, tool := range s.ListTools() {
		result, err := tool.Handler(context.Background(), mcp.CallToolRequest{})
		if err != nil || !result.IsError {
			t.Fatalf("%s did not fail closed", name)
		}
	}
	set := s.ListTools()["aperture_set_config"].Tool
	if !*set.Annotations.DestructiveHint || !strings.Contains(set.Description, "Redacted provider keys") {
		t.Fatal(set)
	}
	for _, deny := range []bool{false, true} {
		s = server.NewMCPServer("aperture", "test")
		c := newTestClient(t, func(*http.Request) (*http.Response, error) {
			if deny {
				t.Fatal("denied request reached upstream")
			}
			return response(200, `{"config":"{}"}`), nil
		})
		checked := ""
		RegisterTools(s, c, func(_ context.Context, name string) error {
			checked = name
			if deny {
				return errors.New("supersecret")
			}
			return nil
		})
		result, err := s.ListTools()["aperture_get_config"].Handler(context.Background(), mcp.CallToolRequest{})
		if err != nil || result.IsError != deny || checked != "aperture_get_config" {
			t.Fatal(result, err, checked)
		}
		encoded, _ := json.Marshal(result)
		if strings.Contains(string(encoded), "supersecret") {
			t.Fatal(string(encoded))
		}
	}
	if _, err := (Client{}).call(context.Background(), operation("get_config"), nil); err == nil {
		t.Fatal("zero client must fail safely")
	}
}

const populatedPricingBody = `{"currency":"USD","cost_bases":["retail"],"units":{"input":{"basis":"token","quantity":1000000}},"models":{"provider/model":{"cost_bases":{"retail":{"source":"embedded","resolved_model":"model","resolver_adjustment":1.125,"effective_pricing":{"input":"0.000000123456789","variable":false},"modes":{"batch":{"source":"embedded","resolved_model":"model","resolver_adjustment":0.5,"effective_pricing":{"output":"2.50"}}}}}}},"configured_adjustments":{"providers":{"provider":{"cost_basis":"retail","cost_basis_source":"explicit","model_cost_map":[{"match":"*","as":"model","adjustment":0.75}]}}}}`

func TestPopulatedPricing(t *testing.T) {
	const body = populatedPricingBody
	c := newTestClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
	result, err := c.call(context.Background(), operation("get_pricing"), nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	for _, want := range []string{`"input":"0.000000123456789"`, `"output":"2.50"`, `"adjustment":0.75`, `"quantity":1000000`} {
		if !strings.Contains(string(encoded), want) {
			t.Fatal(string(encoded))
		}
	}
	for _, replacement := range [][2]string{
		{`"quantity":1000000`, `"quantity":"1000000"`},
		{`"basis":"token"`, `"basis":null`},
		{`"input":"0.000000123456789"`, `"input":1.5`},
		{`"variable":false`, `"variable":"false"`},
		{`"resolver_adjustment":1.125`, `"resolver_adjustment":"1.125"`},
		{`"source":"embedded"`, `"source":null`},
		{`"match":"*"`, `"match":null`},
		{`"model_cost_map":[{"match":"*","as":"model","adjustment":0.75}]`, `"model_cost_map":{}`},
	} {
		bad := strings.ReplaceAll(body, replacement[0], replacement[1])
		if validPricing([]byte(bad)) {
			t.Fatalf("accepted malformed pricing: %s", bad)
		}
	}
}

func TestPricingNullability(t *testing.T) {
	const rate = "models.provider/model.cost_bases.retail"
	const provider = "configured_adjustments.providers.provider"
	for _, tc := range []struct {
		path  string
		value string // Empty means omit the field.
		valid bool
	}{
		{"cost_bases", `[null]`, false},
		{"cost_bases", `["retail",null]`, false},
		{"cost_bases", `[42]`, false},
		{"cost_bases", `{}`, false},
		{"cost_bases", `"retail"`, false},
		{"cost_bases", `null`, true},
		{"cost_bases", `[]`, true},
		{"cost_bases", ``, false},
		{rate + ".modes", `null`, false},
		{rate + ".modes", `[]`, false},
		{rate + ".modes", `{"batch":null}`, false},
		{rate + ".modes", `{}`, true},
		{rate + ".modes", ``, true},
		{provider + ".cost_basis", `null`, false},
		{provider + ".cost_basis", `42`, false},
		{provider + ".cost_basis", `""`, true},
		{provider + ".cost_basis", ``, true},
		{provider + ".model_cost_map", `null`, true},
		{provider + ".model_cost_map", `[]`, true},
		{provider + ".model_cost_map", ``, false},
		{provider + ".model_cost_map", `{}`, false},
		{provider + ".model_cost_map", `"rules"`, false},
		{provider + ".model_cost_map", `[null]`, false},
		{provider + ".model_cost_map", `[{"match":"*","as":"model"},null]`, false},
		{provider + ".model_cost_map", `[[]]`, false},
		{provider + ".model_cost_map", `[{"match":null,"as":"model"}]`, false},
		{provider + ".model_cost_map", `[{"match":"*","as":null}]`, false},
		{provider + ".model_cost_map", `[{"match":"*","as":"model","adjustment":null}]`, false},
		{provider + ".model_cost_map", `[{"match":"*","as":"model","adjustment":"1"}]`, false},
		{provider + ".model_cost_map", `[{"match":"*","as":"model","adjustment":0}]`, true},
		{provider + ".model_cost_map", `[{"match":"*","as":"model"}]`, true},
		{"currency", `null`, false},
		{"units", `null`, false},
		{"units.input", `null`, false},
		{"units.input.quantity", `null`, false},
		{"units.input.basis", `null`, false},
		{"models", `null`, false},
		{"models.provider/model", `null`, false},
		{"models.provider/model.cost_bases", `null`, false},
		{rate, `null`, false},
		{rate + ".source", `null`, false},
		{rate + ".resolved_model", `null`, false},
		{rate + ".resolver_adjustment", `null`, false},
		{rate + ".effective_pricing", `null`, false},
		{rate + ".effective_pricing.input", `null`, false},
		{rate + ".effective_pricing.variable", `null`, false},
		{rate + ".modes.batch.effective_pricing.output", `null`, false},
		{"configured_adjustments", `null`, false},
		{"configured_adjustments.providers", `null`, false},
		{provider, `null`, false},
		{provider + ".cost_basis_source", `null`, false},
	} {
		t.Run(tc.path+"="+tc.value, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal([]byte(populatedPricingBody), &document); err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(tc.path, ".")
			obj := document
			for _, part := range parts[:len(parts)-1] {
				obj = obj[part].(map[string]any)
			}
			key := parts[len(parts)-1]
			if tc.value == "" {
				delete(obj, key)
			} else {
				obj[key] = json.RawMessage(tc.value)
			}
			body, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"get_pricing", "get_model_pricing"} {
				c := newTestClient(t, func(*http.Request) (*http.Response, error) { return response(200, string(body)), nil })
				result, err := c.call(context.Background(), operation(name), map[string]any{"model": "provider/model"})
				if !tc.valid {
					var detail *toolError
					if result != nil || !errors.As(err, &detail) || detail.Message != "Malformed or unexpected Aperture response" {
						t.Fatalf("%s: result=%v error=%v", name, result, err)
					}
				} else {
					if err != nil {
						t.Fatalf("%s: %v", name, err)
					}
					got := result.(map[string]any)["data"].(json.RawMessage)
					if string(got) != string(body) {
						t.Fatalf("response changed: %s", got)
					}
				}
			}
		})
	}
}

func TestValidationErrorsNullability(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{`null`, true}, {`[]`, true}, {`["invalid configuration"]`, true},
		{`[null]`, false}, {`["supersecret",null]`, false}, {`[42]`, false},
		{`{}`, false}, {`"supersecret"`, false}, {`[[]]`, false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			c := newTestClient(t, func(*http.Request) (*http.Response, error) {
				return response(200, `{"valid":false,"errors":`+tc.value+`}`), nil
			})
			result, err := c.call(context.Background(), operation("validate_config"), map[string]any{"config": "{}"})
			if (err == nil) != tc.valid {
				t.Fatalf("result=%v error=%v", result, err)
			}
			if !tc.valid && result != nil {
				t.Fatalf("partial success: %v", result)
			}
			if err != nil && strings.Contains(err.Error(), "supersecret") {
				t.Fatal(err)
			}
		})
	}
}

func TestRecoveryAndStructuredErrors(t *testing.T) {
	for _, panics := range []bool{false, true} {
		s := server.NewMCPServer("aperture", "test")
		c := newTestClient(t, func(*http.Request) (*http.Response, error) {
			if panics {
				panic("supersecret")
			}
			return response(422, `{"detail":"supersecret"}`), nil
		})
		RegisterTools(s, c, func(context.Context, string) error { return nil })
		result, err := s.ListTools()["aperture_get_config"].Handler(context.Background(), mcp.CallToolRequest{})
		if err != nil || !result.IsError {
			t.Fatal(result, err)
		}
		encoded, _ := json.Marshal(result)
		if strings.Contains(string(encoded), "supersecret") {
			t.Fatal(string(encoded))
		}
		if !panics && result.StructuredContent == nil {
			t.Fatal("missing structured status")
		}
	}
}
