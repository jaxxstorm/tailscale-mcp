package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
	"github.com/mark3labs/mcp-go/server"
	tsapi "tailscale.com/client/tailscale/v2"
)

// Both clients use the normal credential machinery, but only a local mock API.
func legacyResponseServer(t *testing.T, handler http.HandlerFunc) *server.MCPServer {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("missing configured authentication")
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}))
	t.Cleanup(api.Close)
	base, err := url.Parse(api.URL)
	if err != nil {
		t.Fatal(err)
	}
	cred := TailscaleCredential{Kind: CredentialBearer, Token: "fixture-token"}
	s, _, err := newConfiguredMCPServer(&tsapi.Client{BaseURL: base, Tailnet: "example.test", Auth: cred.AdminAuth(), HTTP: api.Client()}, readapi.Client{BaseURL: api.URL + "/api/v2", Tailnet: "example.test", HTTPClient: cred.AdminHTTPClient(api.Client(), api.URL)}, false)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func legacyResponseText(t *testing.T, s *server.MCPServer, method string, params any) string {
	t.Helper()
	ctx := withCapabilities(context.Background(), &MCPCapability{Tools: []string{"*"}, Resources: []string{"*"}}, "fixture")
	response := dispatchGrantTest(t, s, ctx, method, params)
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError  bool `json:"isError"`
			Contents []struct {
				Text string `json:"text"`
			} `json:"contents"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Error) > 0 || envelope.Result.IsError {
		t.Fatalf("request failed: %s", raw)
	}
	if method == "resources/read" && len(envelope.Result.Contents) == 1 {
		return envelope.Result.Contents[0].Text
	}
	if method == "tools/call" && len(envelope.Result.Content) == 1 {
		return envelope.Result.Content[0].Text
	}
	t.Fatalf("unexpected response: %s", raw)
	return ""
}

func assertLegacyJSON(t *testing.T, got, want string) {
	t.Helper()
	var actual, expected any
	if err := json.Unmarshal([]byte(got), &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("response fields or shape changed:\ngot: %s\nwant: %s", got, want)
	}
}

func TestLegacyEmptyDeviceListsRemainArrays(t *testing.T) {
	for _, resource := range []bool{true, false} {
		t.Run(fmt.Sprint(resource), func(t *testing.T) {
			s := legacyResponseServer(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"devices":[]}`) })
			method, params := "tools/call", map[string]any{"name": "list_all_devices", "arguments": map[string]any{}}
			if resource {
				method, params = "resources/read", map[string]any{"uri": "tailscale://devices"}
			}
			assertLegacyJSON(t, legacyResponseText(t, s, method, params), `[]`)
		})
	}
}

func TestLegacyResponseErrors(t *testing.T) {
	for _, target := range []struct {
		name, method string
		params       map[string]any
	}{
		{"devices", "resources/read", map[string]any{"uri": "tailscale://devices"}},
		{"device", "resources/read", map[string]any{"uri": "tailscale://device", "arguments": map[string]any{"device": "123"}}},
		{"settings", "resources/read", map[string]any{"uri": "tailscale://tailnet-settings"}},
		{"list", "tools/call", map[string]any{"name": "list_all_devices", "arguments": map[string]any{}}},
		{"lookup", "tools/call", map[string]any{"name": "get_device_info", "arguments": map[string]any{"device": "123"}}},
	} {
		for _, failure := range []string{"upstream", "malformed", "denied"} {
			t.Run(target.name+"/"+failure, func(t *testing.T) {
				s := legacyResponseServer(t, func(w http.ResponseWriter, r *http.Request) {
					if failure == "denied" {
						t.Error("denied request contacted API")
					}
					if failure == "upstream" {
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, `{"message":"fixture denied"}`)
						return
					}
					fmt.Fprint(w, `{broken`)
				})
				grants := &MCPCapability{Tools: []string{"*"}, Resources: []string{"*"}}
				if failure == "denied" {
					grants = &MCPCapability{}
				}
				ctx := withCapabilities(context.Background(), grants, "fixture")
				raw, err := json.Marshal(dispatchGrantTest(t, s, ctx, target.method, target.params))
				if err != nil {
					t.Fatal(err)
				}
				var response struct {
					Error  json.RawMessage `json:"error"`
					Result struct {
						IsError bool `json:"isError"`
					} `json:"result"`
				}
				if err := json.Unmarshal(raw, &response); err != nil {
					t.Fatal(err)
				}
				if len(response.Error) == 0 && !response.Result.IsError {
					t.Fatalf("failure was hidden: %s", raw)
				}
			})
		}
	}
}

func TestLegacyTailnetSettingsPreserveFields(t *testing.T) {
	for _, timeout := range []int{0, 60} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			settings := fmt.Sprintf(`{"devicesApprovalOn":false,"adminConsoleSessionTimeoutMinutes":%d,"futureSetting":{"enabled":true}}`, timeout)
			s := legacyResponseServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v2/tailnet/example.test/settings" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				fmt.Fprint(w, settings)
			})
			assertLegacyJSON(t, legacyResponseText(t, s, "resources/read", map[string]any{"uri": "tailscale://tailnet-settings"}), settings)
		})
	}
}

func TestLegacyDeviceDetailsPreserveFields(t *testing.T) {
	for _, resource := range []bool{true, false} {
		for _, lookup := range []string{"123", "laptop", "100.64.0.1"} {
			t.Run(fmt.Sprintf("resource=%t/%s", resource, lookup), func(t *testing.T) {
				device := `{"id":"123","hostname":"laptop","postureStatus":{"passing":true,"impacting":false,"failingAssertions":[]},"futureField":{"enabled":false}}`
				s := legacyResponseServer(t, func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/api/v2/tailnet/example.test/devices":
						fmt.Fprint(w, `{"devices":[{"id":"other","hostname":"other"},{"id":"123","hostname":"laptop","addresses":["100.64.0.1"]}]}`)
					case "/api/v2/device/123":
						if r.URL.Query().Get("fields") != "all" {
							t.Error("detail request must include all fields")
						}
						fmt.Fprint(w, device)
					default:
						t.Errorf("unexpected path: %s", r.URL.Path)
						http.NotFound(w, r)
					}
				})
				method, params := "tools/call", map[string]any{"name": "get_device_info", "arguments": map[string]any{"device": lookup}}
				if resource {
					method, params = "resources/read", map[string]any{"uri": "tailscale://device", "arguments": map[string]any{"device": lookup}}
				}
				assertLegacyJSON(t, legacyResponseText(t, s, method, params), device)
			})
		}
	}
}

func TestLegacyDeviceListsPreserveFields(t *testing.T) {
	for _, resource := range []bool{true, false} {
		t.Run(fmt.Sprint(resource), func(t *testing.T) {
			devices := `[{"id":"123","hostname":"laptop","addresses":["100.64.0.1"],"postureStatus":{"passing":false,"impacting":true,"failingAssertions":["node:os == 'linux'"]},"futureField":9007199254740993}]`
			s := legacyResponseServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v2/tailnet/example.test/devices" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				wantFields := ""
				if resource {
					wantFields = "all"
				}
				if r.URL.Query().Get("fields") != wantFields {
					t.Errorf("fields = %q, want %q", r.URL.Query().Get("fields"), wantFields)
				}
				fmt.Fprintf(w, `{"devices":%s}`, devices)
			})
			method, params := "tools/call", map[string]any{"name": "list_all_devices", "arguments": map[string]any{}}
			if resource {
				method, params = "resources/read", map[string]any{"uri": "tailscale://devices"}
			}
			got := legacyResponseText(t, s, method, params)
			assertLegacyJSON(t, got, devices)
			// Do not round-trip raw numbers through float64.
			var entries []map[string]json.RawMessage
			if err := json.Unmarshal([]byte(got), &entries); err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || string(entries[0]["futureField"]) != "9007199254740993" {
				t.Error("unknown number lost precision")
			}
		})
	}
}
