package readapi

import "testing"

func TestExpandPathAndQuery(t *testing.T) {
	endpoint := Endpoint{
		Path: "/tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved",
		Parameters: []Parameter{
			RequiredPath("serviceName", ""),
			RequiredPath("deviceId", ""),
			Query("event", "", false),
		},
	}
	path, query, err := Expand(endpoint, "example.com", map[string]any{
		"serviceName": "svc/http",
		"deviceId":    "node 1",
		"event":       []any{"A", "B"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/tailnet/example.com/services/svc%2Fhttp/device/node%201/approved" {
		t.Fatalf("unexpected path %q", path)
	}
	if query != "event=A&event=B" {
		t.Fatalf("unexpected query %q", query)
	}
}

func TestExpandMissingRequiredParameter(t *testing.T) {
	_, _, err := Expand(Endpoint{Path: "/device/{deviceId}", Parameters: []Parameter{RequiredPath("deviceId", "")}}, "-", map[string]any{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSanitizeAPIError(t *testing.T) {
	err := SanitizeAPIError(403, []byte(`{"message":"denied","secret":"ignored"}`))
	if err.StatusCode != 403 || err.Message != "denied" {
		t.Fatalf("unexpected error %#v", err)
	}
}
