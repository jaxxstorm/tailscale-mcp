package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	tsapi "tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
)

func TestParseTailscaleCredentialRequiresValue(t *testing.T) {
	_, err := ParseTailscaleCredential("")
	if err == nil || !strings.Contains(err.Error(), tailscaleOAuthTokenEnv) {
		t.Fatalf("expected missing credential error, got %v", err)
	}
}

func TestParseRawCredentialClassifiesBearer(t *testing.T) {
	cred, err := ParseTailscaleCredential("tskey-api-secret")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Kind != CredentialBearer || cred.Token != "tskey-api-secret" {
		t.Fatalf("unexpected credential %#v", cred)
	}
}

func TestParseRawOAuthClientSecretRequiresClientID(t *testing.T) {
	_, err := ParseTailscaleCredential("tskey-client-secret")
	if err == nil || !strings.Contains(err.Error(), "client ID") {
		t.Fatalf("expected client ID error, got %v", err)
	}
}

func TestParseRawOAuthClientSecretWithClientID(t *testing.T) {
	cred, err := ParseTailscaleCredentialWithClientID("tskey-client-secret", "cid")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Kind != CredentialOAuth || cred.ClientID != "cid" || cred.ClientSecret != "tskey-client-secret" {
		t.Fatalf("unexpected credential %#v", cred)
	}
}

func TestParseOAuthCredentialJSON(t *testing.T) {
	cred, err := ParseTailscaleCredential(`{"type":"oauth","clientId":"cid","clientSecret":"secret","scopes":["all:read"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Kind != CredentialOAuth || cred.ClientID != "cid" || cred.ClientSecret != "secret" || len(cred.Scopes) != 1 {
		t.Fatalf("unexpected credential %#v", cred)
	}
}

func TestParseFederatedCredentialRequiresIDToken(t *testing.T) {
	_, err := ParseTailscaleCredential(`{"type":"federated","clientId":"cid","audience":"aud"}`)
	if err == nil || !strings.Contains(err.Error(), "idToken") {
		t.Fatalf("expected idToken error, got %v", err)
	}
}

func TestStaticBearerAuthSetsAuthorizationHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("Authorization = %q, want %q", got, "Bearer secret")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := staticBearerAuth{Token: "secret"}.HTTPClient(&http.Client{Timeout: time.Second}, "")
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
}

func TestConfigureTSNetUsesSingleCredential(t *testing.T) {
	tests := []struct {
		name string
		cred TailscaleCredential
		want func(*tsnet.Server) bool
	}{
		{
			name: "oauth",
			cred: TailscaleCredential{Kind: CredentialOAuth, ClientID: "cid", ClientSecret: "secret"},
			want: func(s *tsnet.Server) bool { return s.ClientSecret == "secret" && s.AuthKey == "" },
		},
		{
			name: "federated",
			cred: TailscaleCredential{Kind: CredentialFederated, ClientID: "cid", IDToken: "id-token"},
			want: func(s *tsnet.Server) bool { return s.ClientID == "cid" && s.IDToken == "id-token" && s.AuthKey == "" },
		},
		{
			name: "bearer",
			cred: TailscaleCredential{Kind: CredentialBearer, Token: "tskey-auth"},
			want: func(s *tsnet.Server) bool { return s.AuthKey == "tskey-auth" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &tsnet.Server{}
			tt.cred.ConfigureTSNet(server)
			if !tt.want(server) {
				t.Fatalf("unexpected tsnet server configuration: %#v", server)
			}
		})
	}
}

func TestCredentialRequiresTSNetAdvertiseTags(t *testing.T) {
	tests := []struct {
		name string
		cred TailscaleCredential
		want bool
	}{
		{name: "oauth", cred: TailscaleCredential{Kind: CredentialOAuth, ClientSecret: "tskey-client-secret"}, want: true},
		{name: "federated", cred: TailscaleCredential{Kind: CredentialFederated, ClientID: "cid", IDToken: "token"}, want: true},
		{name: "oauth bearer", cred: TailscaleCredential{Kind: CredentialBearer, Token: "tskey-client-secret"}, want: true},
		{name: "auth key bearer", cred: TailscaleCredential{Kind: CredentialBearer, Token: "tskey-auth-secret"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cred.RequiresTSNetAdvertiseTags(); got != tt.want {
				t.Fatalf("RequiresTSNetAdvertiseTags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseAdvertiseTags(t *testing.T) {
	tags, err := parseAdvertiseTags(" tag:mcp-server,tag:ops ")
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || tags[0] != "tag:mcp-server" || tags[1] != "tag:ops" {
		t.Fatalf("unexpected tags %#v", tags)
	}

	if _, err := parseAdvertiseTags("mcp-server"); err == nil {
		t.Fatal("expected invalid tag error")
	}
}

func TestValidateCredentialFormatsValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"missing scope"}`))
	}))
	defer server.Close()

	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &tsapi.Client{BaseURL: baseURL, Tailnet: "example.com", Auth: staticBearerAuth{Token: "secret"}}
	err = ValidateCredential(context.Background(), client)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), tailscaleOAuthTokenEnv) || !strings.Contains(err.Error(), "missing scope") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}
