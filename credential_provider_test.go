package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseProviderCredentials(t *testing.T) {
	for _, provider := range []string{"kubernetes", "aws", "gcp"} {
		for _, explicit := range []bool{false, true} {
			fields := map[string]any{"clientId": " cid ", "provider": provider, "audience": " aud "}
			if explicit {
				fields["type"] = "federated"
			}
			if provider == "kubernetes" {
				fields["tokenFile"] = " /nonexistent/projected/token "
			}
			if provider == "aws" {
				fields["region"] = " us-east-1 "
			}
			raw, _ := json.Marshal(fields)
			cred, err := ParseTailscaleCredential(string(raw))
			if err != nil {
				t.Fatal(err)
			}
			if cred.Kind != CredentialFederated || cred.Provider != provider || cred.Audience != "aud" || cred.ClientID != "cid" {
				t.Fatal("provider configuration was not classified or normalized")
			}
			if provider == "kubernetes" && cred.TokenFile != "/nonexistent/projected/token" {
				t.Fatal("projected path not normalized")
			}
			if provider == "aws" && cred.Region != "us-east-1" {
				t.Fatal("region not normalized")
			}
			if !cred.RequiresTSNetAdvertiseTags() {
				t.Fatal("provider enrollment must require tags")
			}
		}
		// Defaults are resolved only at acquisition; parsing must perform no I/O.
		raw, _ := json.Marshal(map[string]string{"type": "federated", "clientId": "cid", "audience": "aud", "provider": provider})
		if _, err := ParseTailscaleCredential(string(raw)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRejectAmbiguousProviderCredentials(t *testing.T) {
	for _, field := range []string{"clientId", "audience", "provider", "tokenFile", "region"} {
		for _, value := range []any{nil, "", " \t", 42, true, []string{"secret"}, map[string]string{"secret": "value"}} {
			fields := map[string]any{"type": "federated", "clientId": "cid", "provider": "kubernetes", "audience": "aud"}
			if field == "region" {
				fields["provider"] = "aws"
			}
			fields[field] = value
			raw, _ := json.Marshal(fields)
			_, err := ParseTailscaleCredential(string(raw))
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("invalid %s was accepted or disclosed: %v", field, err)
			}
		}
	}
	for _, raw := range []string{
		`{"clientId":"cid","provider":"azure","audience":"aud"}`,
		`{"clientId":"cid","provider":"auto","audience":"aud"}`,
		`{"clientId":"cid","provider":"gcp","audience":"aud","region":"us-east-1"}`,
		`{"clientId":"cid","provider":"aws","audience":"aud","tokenFile":"/token"}`,
		`{"clientId":"cid","idToken":"assertion","tokenFile":"/token"}`,
		`{"type":"oauth","clientId":"cid","clientSecret":"value","provider":"gcp","audience":"aud"}`,
		`{"type":"bearer","token":"value","provider":"gcp","audience":"aud"}`,
		`{"type":"federated","clientId":"cid","clientSecret":"value","provider":"gcp","audience":"aud"}`,
		`{"type":"federated","clientId":"cid","token":"value","provider":"gcp","audience":"aud"}`,
	} {
		if _, err := ParseTailscaleCredential(raw); err == nil {
			t.Fatal("accepted incompatible provider settings")
		}
	}
	for _, field := range []string{"idToken", "idTokenFile"} {
		for _, value := range []any{nil, "", "value"} {
			fields := map[string]any{"clientId": "cid", "provider": "gcp", "audience": "aud", field: value}
			raw, _ := json.Marshal(fields)
			if _, err := ParseTailscaleCredential(string(raw)); err == nil {
				t.Fatal("accepted competing provider and supplied assertion sources")
			}
		}
	}
}
