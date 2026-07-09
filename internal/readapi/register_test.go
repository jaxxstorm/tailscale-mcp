package readapi

import (
	"context"
	"errors"
	"testing"
)

func TestWithAccessDoesNotCallAPIWhenUnauthorized(t *testing.T) {
	called := false
	denied := errors.New("denied")
	_, err := withAccess(context.Background(), "tool:test", func(context.Context, string) error {
		return denied
	}, func() (string, error) {
		called = true
		return "", nil
	})
	if !errors.Is(err, denied) {
		t.Fatalf("expected denied error, got %v", err)
	}
	if called {
		t.Fatal("API helper was called after authorization failed")
	}
}

func TestValidateConfirmation(t *testing.T) {
	endpoint := Endpoint{OperationID: "deleteDevice", Confirm: "deleteDevice"}
	if err := validateConfirmation(endpoint, map[string]any{"confirm": "deleteDevice"}); err != nil {
		t.Fatalf("expected confirmation to pass: %v", err)
	}
	if err := validateConfirmation(endpoint, map[string]any{"confirm": "wrong"}); err == nil {
		t.Fatal("expected confirmation failure")
	}
}

func TestArgumentsFromURI(t *testing.T) {
	args, err := argumentsFromURI("tailscale://device/{deviceId}/routes", "tailscale://device/node-1/routes")
	if err != nil {
		t.Fatal(err)
	}
	if args["deviceId"] != "node-1" {
		t.Fatalf("unexpected deviceId %#v", args["deviceId"])
	}
}
