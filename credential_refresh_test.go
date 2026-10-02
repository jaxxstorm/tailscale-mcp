package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
	tsapi "tailscale.com/client/tailscale/v2"
)

func writeAssertion(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path+".new", []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
}

func assertionJWT(label string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d,"sub":%q}`, time.Now().Add(time.Hour).Unix(), label))) + ".signature"
}

func TestFederatedAssertionSources(t *testing.T) {
	for _, raw := range []string{
		`{"type":"federated","clientId":"cid"}`,
		`{"clientId":"cid","idToken":"secret","idTokenFile":"secret-path"}`,
		`{"type":"federated","clientId":"cid","idToken":" ","idTokenFile":" "}`,
	} {
		if _, err := ParseTailscaleCredential(raw); err == nil {
			t.Fatal("accepted missing or ambiguous assertion sources")
		}
	}
	path := filepath.Join(t.TempDir(), "secret-path")
	raw, _ := json.Marshal(map[string]string{"clientId": "cid", "idTokenFile": " " + path + " "})
	cred, err := ParseTailscaleCredential(string(raw))
	if err != nil || cred.Kind != CredentialFederated {
		t.Fatalf("file credential parse: %v", err)
	}
	writeAssertion(t, path, " \nfirst\t")
	if got, err := cred.assertion(); err != nil || got != "first" {
		t.Fatalf("trimmed assertion failed: %v", err)
	}
	writeAssertion(t, path, "second")
	s, err := newTSNetServer("credential-test", nil, cred, false, tsnetStateConfig{})
	if err != nil || s.IDToken != "second" {
		t.Fatalf("snapshot failed: %v", err)
	}
	for _, state := range []string{"empty", "missing", "unreadable"} {
		t.Run(state, func(t *testing.T) {
			switch state {
			case "empty":
				writeAssertion(t, path, " \n\t")
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "unreadable":
				// A directory reliably fails ReadFile even when tests run as root.
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			server, err := newTSNetServer("credential-test", nil, cred, false, tsnetStateConfig{})
			if err == nil || server != nil || strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "second") {
				t.Fatalf("expected sanitized startup failure, got %v", err)
			}
		})
	}
}

func TestFederatedAdminClientsRefresh(t *testing.T) {
	for _, kind := range []string{"typed", "generic"} {
		for _, failure := range []string{"missing", "empty", "unreadable", "endpoint"} {
			t.Run(kind+"/"+failure, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "assertion")
				first, second := assertionJWT("first-secret"), assertionJWT("second-secret")
				writeAssertion(t, path, " \n"+first+"\t")
				var exchanges, reads atomic.Int32
				var reject atomic.Bool
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if r.URL.Path == "/api/v2/oauth/token-exchange" {
						n := exchanges.Add(1)
						_ = r.ParseForm()
						want := first
						if n > 1 {
							want = second
						}
						if r.Form.Get("jwt") != want || r.Form.Get("client_id") != "cid" {
							t.Error("incorrect exchange assertion/client")
						}
						if reject.Load() {
							w.WriteHeader(http.StatusUnauthorized)
							_, _ = fmt.Fprint(w, second)
							return
						}
						// Already expired access tokens force refresh without expiring the ID token.
						_, _ = fmt.Fprint(w, `{"access_token":"access-secret","token_type":"Bearer","expires_in":-1}`)
						return
					}
					reads.Add(1)
					if r.Header.Get("Authorization") != "Bearer access-secret" {
						t.Error("missing access token")
					}
					_, _ = fmt.Fprint(w, `{}`)
				}))
				defer srv.Close()
				cred := TailscaleCredential{Kind: CredentialFederated, ClientID: "cid", IDTokenFile: path}
				baseURL, _ := url.Parse(srv.URL)
				typed := &tsapi.Client{BaseURL: baseURL, Auth: cred.AdminAuth(), HTTP: srv.Client()}
				generic := readapi.Client{BaseURL: srv.URL, HTTPClient: cred.AdminHTTPClient(srv.Client(), srv.URL)}
				call := func() error {
					if kind == "typed" {
						_, err := typed.TailnetSettings().Get(context.Background())
						return err
					}
					_, err := generic.Do(context.Background(), readapi.Endpoint{Method: "GET", Path: "/api/v2/tailnet/-/settings"}, nil)
					return err
				}
				if err := call(); err != nil {
					t.Fatal(err)
				}
				writeAssertion(t, path, second)
				if err := call(); err != nil {
					t.Fatal(err)
				}
				switch failure {
				case "missing", "unreadable":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if failure == "unreadable" {
						if err := os.Mkdir(path, 0700); err != nil {
							t.Fatal(err)
						}
					}
				case "empty":
					writeAssertion(t, path, " \n")
				case "endpoint":
					reject.Store(true)
				}
				err := call()
				if err == nil {
					t.Fatal("expected authentication failure")
				}
				for _, secret := range []string{first, second, "access-secret", path} {
					if strings.Contains(err.Error(), secret) {
						t.Fatal("error leaked credential material")
					}
				}
				wantExchanges := int32(2)
				if failure == "endpoint" {
					wantExchanges++
				}
				if exchanges.Load() != wantExchanges || reads.Load() != 2 {
					t.Fatal("unexpected exchange or stale-authenticated API request")
				}
			})
		}
	}
}

func TestValidateCredentialBoundsTokenExchange(t *testing.T) {
	for _, kind := range []CredentialKind{CredentialOAuth, CredentialFederated, CredentialBearer} {
		t.Run(string(kind), func(t *testing.T) {
			var canceled atomic.Bool
			base := &http.Client{Transport: credentialRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) > credentialValidationTimeout {
					t.Error("missing validation deadline")
				}
				<-r.Context().Done()
				canceled.Store(true)
				return nil, r.Context().Err()
			})}
			cred := TailscaleCredential{Kind: kind, ClientID: "cid", ClientSecret: "secret", IDToken: assertionJWT("inline"), Token: "bearer"}
			client := &tsapi.Client{HTTP: base, Auth: cred.AdminAuth()}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			if err := ValidateCredential(ctx, client); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected deadline failure: %v", err)
			}
			if !canceled.Load() {
				t.Fatal("exchange did not observe cancellation")
			}
		})
	}
}

func TestFederatedAdminClientsCacheAccessToken(t *testing.T) {
	for _, kind := range []string{"typed", "generic"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "assertion")
			writeAssertion(t, path, assertionJWT("cached"))
			var exchanges atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/api/v2/oauth/token-exchange" {
					exchanges.Add(1)
					_, _ = fmt.Fprint(w, `{"access_token":"cached-access","token_type":"Bearer","expires_in":3600}`)
					return
				}
				_, _ = fmt.Fprint(w, `{}`)
			}))
			defer srv.Close()
			cred := TailscaleCredential{Kind: CredentialFederated, ClientID: "cid", IDTokenFile: path}
			baseURL, _ := url.Parse(srv.URL)
			typed := &tsapi.Client{BaseURL: baseURL, Auth: cred.AdminAuth()}
			generic := readapi.Client{BaseURL: srv.URL, HTTPClient: cred.AdminHTTPClient(srv.Client(), srv.URL)}
			for i := range 2 {
				var err error
				if kind == "typed" {
					_, err = typed.TailnetSettings().Get(context.Background())
				} else {
					_, err = generic.Do(context.Background(), readapi.Endpoint{Method: "GET", Path: "/api/v2/tailnet/-/settings"}, nil)
				}
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
			}
			if exchanges.Load() != 1 {
				t.Fatal("valid access token was not cached")
			}
		})
	}
}

func TestValidateCredentialDefaultDeadlineAndScope(t *testing.T) {
	client := &tsapi.Client{HTTP: &http.Client{Transport: credentialRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		remaining := time.Until(deadline)
		if !ok || remaining > 30*time.Second || remaining < 29*time.Second {
			t.Errorf("validation deadline = %v", remaining)
		}
		if r.Method != "GET" || r.URL.Path != "/api/v2/tailnet/-/settings" {
			t.Errorf("unexpected validation request: %s %s", r.Method, r.URL.Path)
		}
		return nil, context.DeadlineExceeded
	})}}
	if err := ValidateCredential(context.Background(), client); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExistingOAuthAndInlineFederationAuthenticate(t *testing.T) {
	for _, kind := range []CredentialKind{CredentialOAuth, CredentialFederated} {
		t.Run(string(kind), func(t *testing.T) {
			assertion := assertionJWT("inline-secret")
			var exchanges atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasPrefix(r.URL.Path, "/api/v2/oauth/") {
					exchanges.Add(1)
					_ = r.ParseForm()
					if kind == CredentialFederated {
						if r.Form.Get("jwt") != assertion {
							t.Error("inline assertion changed")
						}
					} else {
						id, secret, ok := r.BasicAuth()
						if !ok || id != "cid" || secret != "client-secret" || r.Form.Get("scope") != "all:read" || r.Form.Get("grant_type") != "client_credentials" {
							t.Error("OAuth credentials/scopes changed")
						}
					}
					_, _ = fmt.Fprint(w, `{"access_token":"access","token_type":"Bearer","expires_in":3600}`)
					return
				}
				if r.Header.Get("Authorization") != "Bearer access" {
					t.Error("missing access token")
				}
				_, _ = fmt.Fprint(w, `{}`)
			}))
			defer srv.Close()
			cred := TailscaleCredential{Kind: kind, ClientID: "cid", ClientSecret: "client-secret", IDToken: assertion, Scopes: []string{"all:read"}}
			baseURL, _ := url.Parse(srv.URL)
			client := &tsapi.Client{BaseURL: baseURL, Auth: cred.AdminAuth()}
			if err := ValidateCredential(context.Background(), client); err != nil {
				t.Fatal(err)
			}
			if exchanges.Load() != 1 {
				t.Fatal("expected one token exchange")
			}
		})
	}
}
