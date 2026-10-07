package workloadidentity

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

var testNow = time.Unix(1700000000, 0)

func jwt(claims string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES384"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".c2ln"
}
func validJWT() string { return jwt(`{"aud":"test","exp":1700000300}`) }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Metadata-Flavor": {"Google"}}, Body: io.NopCloser(strings.NewReader(body))}
}
func testSource(rt roundTripFunc) source {
	return source{httpClient: newHTTPClient(rt), now: func() time.Time { return testNow }}
}

func TestConfig(t *testing.T) {
	for _, c := range []Config{
		{Provider: "kubernetes", Audience: "test"}, {Provider: "aws", Audience: "test"}, {Provider: "gcp", Audience: "test"},
		{Provider: "kubernetes", Audience: "test", TokenFile: "/missing"}, {Provider: "aws", Audience: "test", Region: "us-east-1"},
	} {
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []Config{
		{}, {Provider: "secret", Audience: "test"}, {Provider: "aws", Audience: " \t"},
		{Provider: "gcp", Audience: "test", Region: "secret"}, {Provider: "aws", Audience: "test", TokenFile: "secret"},
		{Provider: "kubernetes", Audience: "test", Region: "secret"}, {Provider: "gcp", Audience: "test", TokenFile: "secret"},
		{Provider: "aws", Audience: "test", Region: " \n"}, {Provider: "kubernetes", Audience: "test", TokenFile: " \t"},
	} {
		if err := c.Validate(); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unsafe validation: %v", err)
		}
	}
	s := testSource(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected I/O"); return nil, nil })
	if _, err := s.acquire(context.Background(), Config{Provider: "unknown", Audience: "test"}); err == nil {
		t.Fatal("accepted unknown provider")
	}
}

func TestJWT(t *testing.T) {
	for _, claims := range []string{`{"aud":"test","exp":1700000300}`, `{"aud":["other","test"],"exp":1700000000.5}`} {
		token := jwt(claims)
		if got, err := validateToken(" \n"+token+"\t", "test", testNow); err != nil || got != token {
			t.Fatalf("valid token rejected: %v", err)
		}
	}
	for name, token := range map[string]string{
		"empty": "", "shape": "secret", "empty-segment": "a..b", "base64": "!!!!.aaaa.aaaa",
		"bad-header": "bm90anNvbg." + strings.Split(validJWT(), ".")[1] + ".c2ln",
		"none-alg":   base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + strings.Split(validJWT(), ".")[1] + ".c2ln",
		"no-alg":     "e30." + strings.Split(validJWT(), ".")[1] + ".c2ln",
		"bad-json":   jwt(`secret`), "null": jwt(`null`), "array": jwt(`[]`),
		"expired": jwt(`{"aud":"test","exp":1699999999}`), "now": jwt(`{"aud":"test","exp":1700000000}`),
		"missing-exp": jwt(`{"aud":"test"}`), "string-exp": jwt(`{"aud":"test","exp":"1700000300"}`),
		"null-exp": jwt(`{"aud":"test","exp":null}`), "overflow-exp": jwt(`{"aud":"test","exp":1e999}`),
		"wrong-aud": jwt(`{"aud":"other","exp":1700000300}`), "missing-aud": jwt(`{"exp":1700000300}`),
		"mixed-aud": jwt(`{"aud":["test",42],"exp":1700000300}`), "empty-aud": jwt(`{"aud":[],"exp":1700000300}`),
		"object-aud": jwt(`{"aud":{},"exp":1700000300}`), "oversized": strings.Repeat("x", maxSize+1),
		"newline": strings.Replace(validJWT(), ".", "\n.", 1), "bad-signature": strings.TrimSuffix(validJWT(), "c2ln") + "!",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := validateToken(token, "test", testNow); err == nil || got != "" || strings.Contains(err.Error(), "secret") {
				t.Fatalf("accepted or disclosed invalid token: %v", err)
			}
		})
	}
}

func TestKubernetesRotationAndFailures(t *testing.T) {
	dir := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	first, second := validJWT(), jwt(`{"aud":"test","exp":1700000600}`)
	for name, token := range map[string]string{"v1": first, "v2": second} {
		if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(dir, name, "token"), " \n"+token+"\n")
	}
	link := filepath.Join(dir, "..data")
	if err := os.Symlink("v1", link); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "token")
	if err := os.Symlink("..data/token", path); err != nil {
		t.Fatal(err)
	}
	s := testSource(func(*http.Request) (*http.Response, error) {
		t.Fatal("Kubernetes attempted cloud fallback")
		return nil, nil
	})
	s.loadAWS = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
		t.Fatal("Kubernetes loaded AWS")
		return aws.Config{}, nil
	}
	cfg := Config{Provider: "kubernetes", Audience: "test", TokenFile: path}
	if got, err := s.acquire(context.Background(), cfg); err != nil || got != first {
		t.Fatalf("first: %v", err)
	}
	if err := os.Symlink("v2", link+"-new"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(link+"-new", link); err != nil {
		t.Fatal(err)
	}
	if got, err := s.acquire(context.Background(), cfg); err != nil || got != second {
		t.Fatalf("rotation: %v", err)
	}
	for name, body := range map[string]string{"empty": " \n", "invalid": "secret", "oversized": strings.Repeat("s", maxSize+1)} {
		t.Run(name, func(t *testing.T) {
			write(filepath.Join(dir, "v2", "token"), body)
			if got, err := s.acquire(context.Background(), cfg); err == nil || got != "" || strings.Contains(err.Error(), "secret") {
				t.Fatalf("invalid file: %v", err)
			}
		})
	}
	write(filepath.Join(dir, "v2", "token"), second)
	if err := os.Chmod(filepath.Join(dir, "v2", "token"), 0000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if _, err := s.acquire(context.Background(), cfg); err == nil {
			t.Fatal("accepted unreadable file")
		}
	}
	if err := os.Remove(filepath.Join(dir, "v2", "token")); err != nil {
		t.Fatal(err)
	}
	if got, err := s.acquire(context.Background(), cfg); err == nil || got != "" {
		t.Fatal("missing file reused assertion")
	}
	cfg.TokenFile = dir
	if _, err := s.acquire(context.Background(), cfg); err == nil {
		t.Fatal("accepted directory")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.acquire(ctx, cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestGCP(t *testing.T) {
	t.Setenv("GCE_METADATA_HOST", "secret.invalid")
	t.Setenv("GCE_METADATA_IP", "secret.invalid")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/secret/missing.json")
	audience := "test?&=/ space"
	s := testSource(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Scheme != "http" || r.URL.Host != "metadata.google.internal" || r.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/identity" || r.URL.Query().Get("audience") != audience || r.URL.Query().Get("format") != "full" || len(r.URL.Query()) != 2 || r.Header.Get("Metadata-Flavor") != "Google" {
			t.Fatalf("incorrect request: %v", r)
		}
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > acquisitionTimeout {
			t.Fatal("missing acquisition deadline")
		}
		return response(200, jwt(fmt.Sprintf(`{"aud":%q,"exp":1700000300}`, audience))), nil
	})
	if _, err := s.acquire(context.Background(), Config{Provider: "gcp", Audience: audience}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing-header", "wrong-header", "status", "empty", "invalid", "oversized", "error", "redirect"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			s := testSource(func(*http.Request) (*http.Response, error) {
				calls++
				r := response(200, validJWT())
				switch name {
				case "missing-header":
					r.Header.Del("Metadata-Flavor")
				case "wrong-header":
					r.Header.Set("Metadata-Flavor", "secret")
				case "status":
					r = response(403, "secret")
				case "empty":
					r = response(200, "")
				case "invalid":
					r = response(200, "secret")
				case "oversized":
					r = response(200, strings.Repeat("s", maxSize+1))
				case "error":
					return nil, errors.New("secret")
				case "redirect":
					r = response(302, "secret")
					r.Header.Set("Location", "http://secret.invalid")
				}
				return r, nil
			})
			if got, err := s.acquire(context.Background(), Config{Provider: "gcp", Audience: "test"}); err == nil || got != "" || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe error: %v", err)
			}
			if calls != 1 {
				t.Fatalf("fallback or redirect: %d requests", calls)
			}
		})
	}
}

func TestHTTPPolicyAndCancellation(t *testing.T) {
	c := newHTTPClient(nil)
	defer c.client.CloseIdleConnections()
	if c.client.Timeout != 5*time.Second || c.client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("unsafe HTTP policy")
	}
	if c.client.Transport.(*http.Transport).TLSClientConfig != nil {
		t.Fatal("unexpected TLS override")
	}
	for _, name := range []string{"cancel", "deadline", "request-timeout"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := context.Canceled
			if name == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 10*time.Millisecond)
				defer stop()
				want = context.DeadlineExceeded
			}
			client := newHTTPClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if name == "cancel" {
					cancel()
				}
				<-r.Context().Done()
				return nil, fmt.Errorf("secret: %w", r.Context().Err())
			}))
			if name == "request-timeout" {
				client.client.Timeout = 10 * time.Millisecond
				want = context.DeadlineExceeded
			}
			s := source{httpClient: client}
			if _, err := s.acquire(ctx, Config{Provider: "gcp", Audience: "test"}); !errors.Is(err, want) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("context identity lost: %v", err)
			}
		})
	}
}

func TestBoundedRead(t *testing.T) {
	if b, err := readBounded(strings.NewReader(strings.Repeat("x", maxSize))); err != nil || len(b) != maxSize {
		t.Fatal("rejected exact bound")
	}
	if _, err := readBounded(strings.NewReader(strings.Repeat("x", maxSize+1))); err == nil {
		t.Fatal("accepted overflow")
	}
}

type failingBody struct{ closed bool }

func (*failingBody) Read([]byte) (int, error) {
	return 0, fmt.Errorf("secret: %w", context.DeadlineExceeded)
}
func (b *failingBody) Close() error { b.closed = true; return nil }

func TestResponseReadFailure(t *testing.T) {
	body := &failingBody{}
	s := testSource(func(*http.Request) (*http.Response, error) { r := response(200, ""); r.Body = body; return r, nil })
	if got, err := s.acquire(context.Background(), Config{Provider: "gcp", Audience: "test"}); got != "" || !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe body failure: %v", err)
	}
	if !body.closed {
		t.Fatal("response body not closed")
	}
}

func TestCancellationAfterAcquisition(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := testSource(func(*http.Request) (*http.Response, error) { return response(200, validJWT()), nil })
	s.now = func() time.Time { cancel(); return testNow }
	if got, err := s.acquire(ctx, Config{Provider: "gcp", Audience: "test"}); got != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("returned token after cancellation: %v", err)
	}
}
