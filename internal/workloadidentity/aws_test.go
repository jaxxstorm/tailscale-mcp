package workloadidentity

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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type stsFunc func(context.Context, *sts.GetWebIdentityTokenInput) (*sts.GetWebIdentityTokenOutput, error)

func (f stsFunc) GetWebIdentityToken(ctx context.Context, in *sts.GetWebIdentityTokenInput, _ ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error) {
	return f(ctx, in)
}

func TestAWSBoundary(t *testing.T) {
	for _, regionSource := range []string{"explicit", "sdk", "imds"} {
		t.Run(regionSource, func(t *testing.T) {
			loads, discoveries, calls := 0, 0, 0
			s := testSource(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected HTTP"); return nil, nil })
			s.loadAWS = func(ctx context.Context, opts ...func(*config.LoadOptions) error) (aws.Config, error) {
				loads++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > acquisitionTimeout {
					t.Fatal("unbounded config loading")
				}
				var options config.LoadOptions
				for _, opt := range opts {
					if err := opt(&options); err != nil {
						t.Fatal(err)
					}
				}
				bound, ok := options.HTTPClient.(acquisitionClient)
				if !ok || bound.client != s.httpClient || bound.ctx != ctx || options.RetryMaxAttempts != 3 {
					t.Fatal("unsafe AWS options")
				}
				if regionSource == "explicit" && options.Region != "explicit-region" {
					t.Fatal("explicit region not passed to config loader")
				}
				if regionSource == "imds" {
					return aws.Config{}, nil
				}
				return aws.Config{Region: "sdk-region"}, nil
			}
			s.awsRegion = func(context.Context, aws.Config) (string, error) { discoveries++; return "imds-region", nil }
			s.newSTS = func(c aws.Config) stsClient {
				if c.Region != regionSource+"-region" {
					t.Fatalf("wrong region: %q", c.Region)
				}
				return stsFunc(func(ctx context.Context, in *sts.GetWebIdentityTokenInput) (*sts.GetWebIdentityTokenOutput, error) {
					calls++
					if len(in.Audience) != 1 || in.Audience[0] != "test" || aws.ToString(in.SigningAlgorithm) != "ES384" || aws.ToInt32(in.DurationSeconds) != 300 || len(in.Tags) != 0 {
						t.Fatalf("wrong STS input: %#v", in)
					}
					return &sts.GetWebIdentityTokenOutput{WebIdentityToken: aws.String(validJWT())}, nil
				})
			}
			cfg := Config{Provider: "aws", Audience: "test"}
			if regionSource == "explicit" {
				cfg.Region = "explicit-region"
			}
			for i := 0; i < 2; i++ {
				if got, err := s.acquire(context.Background(), cfg); err != nil || got != validJWT() {
					t.Fatalf("acquisition: %v", err)
				}
			}
			if loads != 2 || calls != 2 {
				t.Fatal("assertion or config unexpectedly cached")
			}
			if (regionSource == "imds" && discoveries != 2) || (regionSource != "imds" && discoveries != 0) {
				t.Fatalf("wrong IMDS calls: %d", discoveries)
			}
		})
	}
}

func TestAWSFailures(t *testing.T) {
	for _, stage := range []string{"config", "region", "empty-region", "credentials", "permission", "nil-output", "nil-token", "empty-token", "invalid-token", "oversized-token", "config-cancel", "region-cancel", "sts-cancel"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := testSource(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected HTTP or fallback"); return nil, nil })
			s.loadAWS = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
				if stage == "config" {
					return aws.Config{}, errors.New("secret")
				}
				if stage == "config-cancel" {
					cancel()
					return aws.Config{}, fmt.Errorf("secret: %w", context.Canceled)
				}
				if strings.HasPrefix(stage, "region") || stage == "empty-region" {
					return aws.Config{}, nil
				}
				return aws.Config{Region: "us-east-1"}, nil
			}
			s.awsRegion = func(context.Context, aws.Config) (string, error) {
				if stage == "region-cancel" {
					cancel()
					return "", fmt.Errorf("secret: %w", context.Canceled)
				}
				if stage == "empty-region" {
					return "", nil
				}
				return "", errors.New("secret")
			}
			s.newSTS = func(aws.Config) stsClient {
				return stsFunc(func(context.Context, *sts.GetWebIdentityTokenInput) (*sts.GetWebIdentityTokenOutput, error) {
					switch stage {
					case "credentials", "permission":
						return nil, errors.New("secret")
					case "sts-cancel":
						cancel()
						return nil, fmt.Errorf("secret: %w", context.Canceled)
					case "nil-output":
						return nil, nil
					case "nil-token":
						return &sts.GetWebIdentityTokenOutput{}, nil
					case "empty-token":
						return &sts.GetWebIdentityTokenOutput{WebIdentityToken: aws.String("")}, nil
					case "invalid-token":
						return &sts.GetWebIdentityTokenOutput{WebIdentityToken: aws.String("secret")}, nil
					case "oversized-token":
						return &sts.GetWebIdentityTokenOutput{WebIdentityToken: aws.String(strings.Repeat("s", maxSize+1))}, nil
					default:
						t.Fatal("STS reached after earlier failure")
						return nil, nil
					}
				})
			}
			got, err := s.acquire(ctx, Config{Provider: "aws", Audience: "test"})
			if err == nil || got != "" || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe result: %v", err)
			}
			if strings.HasSuffix(stage, "cancel") && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
		})
	}
}

func TestAWSWire(t *testing.T) {
	for _, mode := range []string{"success", "redirect", "oversized", "credentials-error", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			s := testSource(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Host != "sts.us-west-2.amazonaws.com" || r.URL.Scheme != "https" {
					t.Fatalf("wrong regional endpoint: %v", r.URL)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				values, err := url.ParseQuery(string(body))
				if err != nil {
					t.Fatal(err)
				}
				if values.Get("Action") != "GetWebIdentityToken" || values.Get("Audience.member.1") != "test" || values.Get("SigningAlgorithm") != "ES384" || values.Get("DurationSeconds") != "300" {
					t.Fatalf("wrong wire parameters: %v", values)
				}
				if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
					t.Fatal("request not signed")
				}
				if mode == "redirect" {
					resp := response(307, "secret")
					resp.Header.Set("Location", "https://secret.invalid")
					return resp, nil
				}
				if mode == "oversized" {
					return response(200, strings.Repeat("s", maxSize+1)), nil
				}
				if mode == "deadline" {
					<-r.Context().Done()
					return nil, fmt.Errorf("secret: %w", r.Context().Err())
				}
				return response(200, `<GetWebIdentityTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetWebIdentityTokenResult><WebIdentityToken>`+validJWT()+`</WebIdentityToken></GetWebIdentityTokenResult></GetWebIdentityTokenResponse>`), nil
			})
			s.loadAWS = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
				var provider aws.CredentialsProvider = credentials.NewStaticCredentialsProvider("fake-access-key", "fake-secret", "fake-session")
				if mode == "credentials-error" {
					provider = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return aws.Credentials{}, errors.New("secret") })
				}
				return aws.Config{Region: "us-west-2", HTTPClient: s.httpClient, Credentials: provider, RetryMaxAttempts: 1}, nil
			}
			ctx := context.Background()
			if mode == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer cancel()
			}
			got, err := s.acquire(ctx, Config{Provider: "aws", Audience: "test"})
			if mode == "success" {
				if err != nil || got != validJWT() {
					t.Fatalf("wire success: %v", err)
				}
			} else if err == nil || got != "" || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe wire failure: %v", err)
			}
			if mode == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("lost deadline: %v", err)
			}
			if mode == "credentials-error" {
				if calls != 0 {
					t.Fatal("request sent without credentials")
				}
			} else if calls != 1 {
				t.Fatalf("unexpected follow-up request: %d", calls)
			}
		})
	}
}

func TestAWSConfigRegionPrecedence(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "config")
	if err := os.WriteFile(shared, []byte("[default]\nregion = eu-west-1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", shared)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "absent"))
	t.Setenv("AWS_PROFILE", "default")
	t.Setenv("AWS_DEFAULT_PROFILE", "default")
	t.Setenv("AWS_ACCESS_KEY_ID", "fake-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fake-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	for _, tc := range []struct{ name, explicit, env, want string }{{"explicit", "ap-south-1", "us-east-2", "ap-south-1"}, {"environment", "", "us-east-2", "us-east-2"}, {"shared", "", "", "eu-west-1"}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AWS_REGION", tc.env)
			s := testSource(func(*http.Request) (*http.Response, error) { t.Fatal("config performed network I/O"); return nil, nil })
			s.awsRegion = func(context.Context, aws.Config) (string, error) {
				t.Fatal("unnecessary region metadata")
				return "", nil
			}
			s.newSTS = func(c aws.Config) stsClient {
				if c.Region != tc.want {
					t.Fatalf("region = %q, want %q", c.Region, tc.want)
				}
				return stsFunc(func(context.Context, *sts.GetWebIdentityTokenInput) (*sts.GetWebIdentityTokenOutput, error) {
					return &sts.GetWebIdentityTokenOutput{WebIdentityToken: aws.String(validJWT())}, nil
				})
			}
			if _, err := s.acquire(context.Background(), Config{Provider: "aws", Audience: "test", Region: tc.explicit}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAWSIMDSRegion(t *testing.T) {
	t.Setenv("AWS_EC2_METADATA_DISABLED", "false")
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", "")
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE", "IPv4")
	for _, mode := range []string{"success", "invalid", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			s := testSource(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Host != "169.254.169.254" {
					t.Fatalf("unexpected metadata host: %s", r.URL.Host)
				}
				if r.Method == "PUT" && r.URL.Path == "/latest/api/token" {
					resp := response(200, "fake-imds-token")
					resp.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "300")
					return resp, nil
				}
				if r.Method != "GET" || r.URL.Path != "/latest/dynamic/instance-identity/document" || r.Header.Get("X-aws-ec2-metadata-token") != "fake-imds-token" {
					t.Fatalf("unexpected IMDS request: %v", r)
				}
				switch mode {
				case "invalid":
					return response(200, "secret"), nil
				case "redirect":
					resp := response(302, "secret")
					resp.Header.Set("Location", "http://secret.invalid")
					return resp, nil
				default:
					return response(200, `{"region":"us-west-2"}`), nil
				}
			})
			s.loadAWS = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
				return aws.Config{HTTPClient: s.httpClient, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}, nil
			}
			s.newSTS = func(c aws.Config) stsClient {
				if mode != "success" {
					t.Fatal("STS reached after metadata failure")
				}
				if c.Region != "us-west-2" {
					t.Fatalf("wrong discovered region: %q", c.Region)
				}
				return stsFunc(func(context.Context, *sts.GetWebIdentityTokenInput) (*sts.GetWebIdentityTokenOutput, error) {
					return &sts.GetWebIdentityTokenOutput{WebIdentityToken: aws.String(validJWT())}, nil
				})
			}
			got, err := s.acquire(context.Background(), Config{Provider: "aws", Audience: "test"})
			if mode == "success" {
				if err != nil || got != validJWT() {
					t.Fatalf("IMDS acquisition: %v", err)
				}
			} else if err == nil || got != "" || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe IMDS failure: %v", err)
			}
			if calls != 2 {
				t.Fatalf("unexpected metadata requests: %d", calls)
			}
		})
	}
}

func TestAcquisitionDeadline(t *testing.T) {
	for _, shorter := range []bool{false, true} {
		ctx := context.Background()
		var want time.Time
		if shorter {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Second)
			defer cancel()
			want, _ = ctx.Deadline()
		}
		s := source{loadAWS: func(ctx context.Context, _ ...func(*config.LoadOptions) error) (aws.Config, error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("missing acquisition deadline")
			}
			if shorter {
				if !deadline.Equal(want) {
					t.Fatal("extended caller deadline")
				}
			} else if remaining := time.Until(deadline); remaining > 30*time.Second || remaining < 29*time.Second {
				t.Fatalf("incorrect acquisition budget: %v", remaining)
			}
			return aws.Config{}, fmt.Errorf("secret: %w", context.DeadlineExceeded)
		}}
		if _, err := s.acquire(ctx, Config{Provider: "aws", Audience: "test"}); !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unsafe deadline error: %v", err)
		}
	}
}

func TestAWSCredentialsCacheCancelsUnderlyingHTTP(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := context.Canceled
			if mode == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 100*time.Millisecond)
				defer stop()
				want = context.DeadlineExceeded
			}
			started := make(chan struct{})
			stopped := make(chan struct{})
			refreshDone := make(chan error, 1)
			release := make(chan struct{})
			defer close(release)
			var sends atomic.Int32
			s := testSource(func(r *http.Request) (*http.Response, error) {
				if sends.Add(1) != 1 {
					return nil, errors.New("unexpected follow-up send")
				}
				close(started)
				select {
				case <-r.Context().Done():
					close(stopped)
					return nil, r.Context().Err()
				case <-release:
					return nil, errors.New("test cleanup")
				}
			})
			s.loadAWS = func(_ context.Context, opts ...func(*config.LoadOptions) error) (aws.Config, error) {
				var options config.LoadOptions
				for _, opt := range opts {
					if err := opt(&options); err != nil {
						return aws.Config{}, err
					}
				}
				cache := aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(detached context.Context) (aws.Credentials, error) {
					// Exercise the SDK's actual suppressedContext rather than simulating
					// cancellation only at the top-level STS call.
					if detached.Done() != nil {
						refreshDone <- errors.New("SDK did not suppress cancellation")
						return aws.Credentials{}, errors.New("unexpected context")
					}
					req, err := http.NewRequestWithContext(detached, "GET", "http://offline.invalid/credentials", nil)
					if err != nil {
						refreshDone <- err
						return aws.Credentials{}, err
					}
					resp, firstErr := options.HTTPClient.Do(req)
					if resp != nil {
						resp.Body.Close()
					}
					// A detached provider may retry or try another credential endpoint.
					// That must fail locally without another transport invocation.
					resp, retryErr := options.HTTPClient.Do(req.Clone(detached))
					if resp != nil {
						resp.Body.Close()
					}
					if firstErr == nil || !errors.Is(retryErr, want) {
						refreshDone <- fmt.Errorf("incorrect refresh failures: first=%v retry=%v", firstErr, retryErr)
					} else {
						refreshDone <- nil
					}
					return aws.Credentials{}, firstErr
				}))
				return aws.Config{Region: "us-west-2", HTTPClient: options.HTTPClient, Credentials: cache, RetryMaxAttempts: 1}, nil
			}
			result := make(chan error, 1)
			go func() { _, err := s.acquire(ctx, Config{Provider: "aws", Audience: "test"}); result <- err }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("credential request did not start")
			}
			if mode == "cancel" {
				cancel()
			}
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("underlying credential HTTP request outlived acquisition")
			}
			select {
			case err := <-refreshDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("credential refresh did not stop")
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatalf("acquisition error: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("acquisition did not stop")
			}
			if sends.Load() != 1 {
				t.Fatalf("sent %d requests after cancellation", sends.Load()-1)
			}
		})
	}
}
