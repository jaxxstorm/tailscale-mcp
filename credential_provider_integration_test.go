package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaxxstorm/tailscale-mcp/internal/readapi"
	"github.com/jaxxstorm/tailscale-mcp/internal/workloadidentity"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	tsapi "tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
)

func TestProviderEnrollmentErrorSanitization(t *testing.T) {
	for _, cause := range []error{errors.New("exchange response contains secret-jwt"), fmt.Errorf("secret-jwt: %w", context.Canceled), fmt.Errorf("secret-jwt: %w", context.DeadlineExceeded)} {
		core, logs := observer.New(zap.ErrorLevel)
		s := testTailnetServer{start: func() error { return cause }}
		err := serveMCPHTTP(context.Background(), s, nil, CLI{Aperture: true}, 8080, 8080, nil)
		if err == nil || strings.Contains(err.Error(), "secret-jwt") {
			t.Fatalf("unsafe enrollment error: %v", err)
		}
		for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
			if errors.Is(err, sentinel) != errors.Is(cause, sentinel) {
				t.Fatal("enrollment error lost cancellation identity")
			}
		}
		zap.New(core).Error("MCP server failed", zap.Error(err))
		if strings.Contains(fmt.Sprint(logs.All()), "secret-jwt") {
			t.Fatal("startup logging exposed token-exchange body")
		}
	}
}

func providerAPIRequest(kind string, cred TailscaleCredential, transport http.RoundTripper) func(context.Context, bool) error {
	base := &http.Client{Transport: transport}
	u, _ := url.Parse("https://offline.invalid")
	typed := &tsapi.Client{BaseURL: u, HTTP: base, Auth: cred.AdminAuth()}
	generic := readapi.Client{BaseURL: u.String(), HTTPClient: cred.AdminHTTPClient(base, u.String())}
	return func(ctx context.Context, mutation bool) error {
		if kind == "typed" {
			if mutation {
				return typed.Devices().Delete(ctx, "test-device")
			}
			_, err := typed.TailnetSettings().Get(ctx)
			return err
		}
		endpoint := readapi.Endpoint{Method: "GET", Path: "/api/v2/tailnet/-/settings"}
		if mutation {
			endpoint = readapi.Endpoint{Method: "DELETE", Path: "/api/v2/device/test-device"}
		}
		_, err := generic.Do(ctx, endpoint, nil)
		return err
	}
}

func providerResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func TestProviderAdminRefreshAndCache(t *testing.T) {
	for _, kind := range []string{"typed", "generic"} {
		for _, cached := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cached=%v", kind, cached), func(t *testing.T) {
				var acquisitions, exchanges, protected int
				assertions := []string{assertionJWT("first"), assertionJWT("rotated")}
				fail := false
				cred := TailscaleCredential{Kind: CredentialFederated, ClientID: "cid", Provider: "aws", Audience: "aud", Region: "us-east-1"}
				cred.acquireProvider = func(ctx context.Context, cfg workloadidentity.Config) (string, error) {
					acquisitions++
					if cfg.Provider != cred.Provider || cfg.Audience != cred.Audience || cfg.Region != cred.Region {
						t.Error("provider configuration changed")
					}
					if fail {
						return "", errors.New("provider-secret")
					}
					return assertions[acquisitions-1], nil
				}
				call := providerAPIRequest(kind, cred, credentialRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/api/v2/oauth/token-exchange" {
						exchanges++
						_ = r.ParseForm()
						if exchanges > len(assertions) || r.Form.Get("jwt") != assertions[exchanges-1] {
							t.Error("stale assertion exchanged")
						}
						expires := -1
						if cached {
							expires = 3600
						}
						return providerResponse(r, 200, fmt.Sprintf(`{"access_token":"access-secret","token_type":"Bearer","expires_in":%d}`, expires)), nil
					}
					protected++
					if r.Header.Get("Authorization") != "Bearer access-secret" {
						t.Error("missing access token")
					}
					return providerResponse(r, 200, `{}`), nil
				}))
				for range 2 {
					if err := call(context.Background(), false); err != nil {
						t.Fatal(err)
					}
				}
				fail = true
				err := call(context.Background(), true)
				if cached {
					if err != nil || acquisitions != 1 || exchanges != 1 || protected != 3 {
						t.Fatalf("cache: %v acquisitions=%d exchanges=%d protected=%d", err, acquisitions, exchanges, protected)
					}
				} else {
					if err == nil || strings.Contains(err.Error(), "provider-secret") || acquisitions != 3 || exchanges != 2 || protected != 2 {
						t.Fatalf("failed refresh dispatched or replayed mutation: %v acquisitions=%d exchanges=%d protected=%d", err, acquisitions, exchanges, protected)
					}
				}
			})
		}
	}
}

func TestProviderAdminCancellation(t *testing.T) {
	for _, kind := range []string{"typed", "generic"} {
		for _, stage := range []string{"provider", "exchange", "lock"} {
			t.Run(kind+"/"+stage, func(t *testing.T) {
				entered := make(chan struct{})
				var acquisitions, exchanges, protected atomic.Int32
				cred := TailscaleCredential{Kind: CredentialFederated, ClientID: "cid", Provider: "gcp", Audience: "aud"}
				cred.acquireProvider = func(ctx context.Context, _ workloadidentity.Config) (string, error) {
					acquisitions.Add(1)
					if stage != "exchange" {
						close(entered)
						<-ctx.Done()
						return "", ctx.Err()
					}
					return assertionJWT("cancel"), nil
				}
				call := providerAPIRequest(kind, cred, credentialRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/api/v2/oauth/token-exchange" {
						exchanges.Add(1)
						close(entered)
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
					protected.Add(1)
					return providerResponse(r, 200, `{}`), nil
				}))
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- call(ctx, true) }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("refresh did not start")
				}
				if stage == "lock" {
					waitCtx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
					defer stop()
					if err := call(waitCtx, true); !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("lock wait: %v", err)
					}
				}
				cancel()
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancellation: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("cancellation hung")
				}
				wantExchanges := int32(0)
				if stage == "exchange" {
					wantExchanges = 1
				}
				if acquisitions.Load() != 1 || exchanges.Load() != wantExchanges || protected.Load() != 0 {
					t.Fatal("canceled request dispatched or reacquired")
				}
			})
		}
	}
}

func TestProviderExchangeFailureDoesNotDispatchMutation(t *testing.T) {
	for _, kind := range []string{"typed", "generic"} {
		t.Run(kind, func(t *testing.T) {
			var acquisitions, exchanges, mutations int
			cred := TailscaleCredential{Kind: CredentialFederated, ClientID: "cid", Provider: "gcp", Audience: "aud"}
			cred.acquireProvider = func(context.Context, workloadidentity.Config) (string, error) {
				acquisitions++
				return assertionJWT("exchange-secret"), nil
			}
			call := providerAPIRequest(kind, cred, credentialRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/api/v2/oauth/token-exchange" {
					exchanges++
					return providerResponse(r, http.StatusForbidden, `{"message":"exchange-secret"}`), nil
				}
				mutations++
				return providerResponse(r, 200, `{}`), nil
			}))
			err := call(context.Background(), true)
			if err == nil || strings.Contains(err.Error(), "exchange-secret") || acquisitions != 1 || exchanges != 1 || mutations != 0 {
				t.Fatalf("exchange failure dispatched/replayed mutation or leaked secret: %v acquisitions=%d exchanges=%d mutations=%d", err, acquisitions, exchanges, mutations)
			}
		})
	}
}

func TestProviderValidationSharedDeadline(t *testing.T) {
	for _, short := range []bool{false, true} {
		for _, failure := range []string{"provider", "exchange", "validation"} {
			t.Run(fmt.Sprintf("short=%v/%s", short, failure), func(t *testing.T) {
				ctx := context.Background()
				if short {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, time.Second)
					defer cancel()
				}
				var deadline time.Time
				callerDeadline, hasCallerDeadline := ctx.Deadline()
				var exchanges, validations int
				cred := TailscaleCredential{Kind: CredentialFederated, ClientID: "cid", Provider: "gcp", Audience: "aud"}
				cred.acquireProvider = func(ctx context.Context, _ workloadidentity.Config) (string, error) {
					var ok bool
					deadline, ok = ctx.Deadline()
					if !ok || time.Until(deadline) > credentialValidationTimeout {
						t.Error("unbounded acquisition")
					}
					if hasCallerDeadline {
						if !deadline.Equal(callerDeadline) {
							t.Error("caller deadline extended")
						}
					}
					if failure == "provider" {
						return "", errors.New("validation-secret")
					}
					return assertionJWT("validation"), nil
				}
				base := &http.Client{Transport: credentialRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					got, ok := r.Context().Deadline()
					if !ok || !got.Equal(deadline) {
						t.Error("validation stages did not share deadline")
					}
					if r.URL.Path == "/api/v2/oauth/token-exchange" {
						exchanges++
						if failure == "exchange" {
							return providerResponse(r, 403, `validation-secret`), nil
						}
						return providerResponse(r, 200, `{"access_token":"access-secret","token_type":"Bearer","expires_in":3600}`), nil
					}
					validations++
					if r.Method != "GET" || r.URL.Path != "/api/v2/tailnet/-/settings" {
						t.Error("validation scope changed")
					}
					return providerResponse(r, 403, `validation-secret`), nil
				})}
				err := ValidateCredential(ctx, &tsapi.Client{HTTP: base, Auth: cred.AdminAuth()})
				if err == nil || strings.Contains(err.Error(), "validation-secret") || strings.Contains(err.Error(), "access-secret") {
					t.Fatalf("unsanitized validation failure: %v", err)
				}
				if (failure == "provider" && exchanges != 0) || (failure != "validation" && validations != 0) {
					t.Fatal("failed stage did not stop validation")
				}
			})
		}
	}
}

func TestProviderTSNetSnapshot(t *testing.T) {
	for _, name := range []string{"TS_AUDIENCE", "TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET"} {
		t.Setenv(name, "")
	}
	t.Setenv("TS_CLIENT_ID", "ambient-client")
	t.Setenv("TS_ID_TOKEN", "ambient-token")
	for _, source := range []string{"provider", "inline", "file"} {
		t.Run(source, func(t *testing.T) {
			cred := TailscaleCredential{Kind: CredentialFederated, ClientID: "explicit-client", Audience: "aud"}
			token := assertionJWT(source)
			calls := 0
			switch source {
			case "provider":
				cred.Provider, cred.TokenFile = "kubernetes", "/projected/token"
				cred.acquireProvider = func(ctx context.Context, cfg workloadidentity.Config) (string, error) {
					calls++
					if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 30*time.Second {
						t.Error("unbounded snapshot")
					}
					if cfg.TokenFile != cred.TokenFile || cfg.Audience != cred.Audience || cfg.Provider != cred.Provider {
						t.Error("snapshot provider configuration changed")
					}
					return token, nil
				}
			case "inline":
				cred.IDToken = token
			case "file":
				cred.IDTokenFile = filepath.Join(t.TempDir(), "assertion")
				writeAssertion(t, cred.IDTokenFile, token)
			}
			s, err := newTSNetServer(context.Background(), "provider-test", []string{"tag:test"}, cred, false, tsnetStateConfig{})
			if err != nil {
				t.Fatal(err)
			}
			if s.ClientID != cred.ClientID || s.IDToken != token || s.Audience != "" || s.AuthKey != "" || s.ClientSecret != "" {
				t.Fatal("competing or ambient tsnet credential selected")
			}
			if source == "provider" && calls != 1 {
				t.Fatal("snapshot not acquired exactly once")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if s, err := newTSNetServer(ctx, "provider-test", nil, cred, false, tsnetStateConfig{}); s != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled startup: %v", err)
			}
		})
	}
}

func TestProviderTSNetEnvironmentGuard(t *testing.T) {
	for _, name := range []string{"TS_AUDIENCE", "TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET"} {
		t.Setenv(name, "")
	}
	for _, name := range []string{"TS_AUDIENCE", "TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "ambient-secret")
			cred := TailscaleCredential{Kind: CredentialFederated, ClientID: "cid", Provider: "gcp", Audience: "aud", acquireProvider: func(context.Context, workloadidentity.Config) (string, error) {
				t.Fatal("acquired before environment validation")
				return "", nil
			}}
			s := &tsnet.Server{ClientID: "unchanged", IDToken: "unchanged", Audience: "unchanged"}
			err := cred.ConfigureTSNet(context.Background(), s)
			if err == nil || !strings.Contains(err.Error(), name) || strings.Contains(err.Error(), "ambient-secret") {
				t.Fatalf("environment rejection: %v", err)
			}
			if os.Getenv(name) != "ambient-secret" || s.ClientID != "unchanged" || s.IDToken != "unchanged" || s.Audience != "unchanged" {
				t.Fatal("failed setup mutated environment or server")
			}
			if err := (TailscaleCredential{Kind: CredentialBearer, Token: "key"}).validateTSNetEnvironment(); err != nil {
				t.Fatal("guard affected non-federated credentials")
			}
		})
	}
}

func TestProviderTSNetAcquisitionFailure(t *testing.T) {
	for _, name := range []string{"TS_AUDIENCE", "TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET"} {
		t.Setenv(name, "")
	}
	for _, failure := range []string{"missing", "canceled", "deadline"} {
		t.Run(failure, func(t *testing.T) {
			cred := TailscaleCredential{Kind: CredentialFederated, ClientID: "cid", Provider: "kubernetes", Audience: "aud", TokenFile: filepath.Join(t.TempDir(), "private-path")}
			ctx := context.Background()
			var want error
			if failure != "missing" {
				var cancel context.CancelFunc
				if failure == "canceled" {
					ctx, cancel = context.WithCancel(ctx)
					want = context.Canceled
				} else {
					ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
					want = context.DeadlineExceeded
				}
				defer cancel()
				cred.acquireProvider = func(ctx context.Context, _ workloadidentity.Config) (string, error) {
					if failure == "canceled" {
						cancel()
					}
					<-ctx.Done()
					return "", ctx.Err()
				}
			}
			s := &tsnet.Server{ClientID: "original-client", IDToken: "original-token", Audience: "original-audience"}
			err := cred.ConfigureTSNet(ctx, s)
			if err == nil || (want != nil && !errors.Is(err, want)) || strings.Contains(err.Error(), cred.TokenFile) {
				t.Fatalf("startup acquisition error: %v", err)
			}
			if s.ClientID != "original-client" || s.IDToken != "original-token" || s.Audience != "original-audience" {
				t.Fatal("failed acquisition partially configured server")
			}
		})
	}
}
