package workloadidentity

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}
type boundedClient struct{ client *http.Client }

// AWS credential caches suppress the request context's cancellation. Bind every
// SDK HTTP call to this acquisition as well, including detached refresh work.
type acquisitionClient struct {
	ctx    context.Context
	client httpDoer
}

func (c acquisitionClient) Do(req *http.Request) (*http.Response, error) {
	var ctx context.Context
	var cancel context.CancelFunc
	if deadline, ok := c.ctx.Deadline(); ok {
		ctx, cancel = context.WithDeadline(req.Context(), deadline)
	} else {
		ctx, cancel = context.WithCancel(req.Context())
	}
	stop := context.AfterFunc(c.ctx, cancel)
	cleanup := func() { stop(); cancel() }
	err := c.ctx.Err()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		cleanup()
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	resp, err := c.client.Do(req.Clone(ctx))
	if err != nil {
		cleanup()
		return nil, err
	}
	// Do may return before body consumption. Keep cancellation attached until
	// the caller closes the body rather than cancelling at response headers.
	resp.Body = &acquisitionBody{ReadCloser: resp.Body, cleanup: cleanup}
	return resp, nil
}

type acquisitionBody struct {
	io.ReadCloser
	cleanup func()
}

func (b *acquisitionBody) Close() error {
	b.cleanup()
	return b.ReadCloser.Close()
}

func newHTTPClient(transport http.RoundTripper) *boundedClient {
	if transport == nil {
		transport = &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: requestTimeout}).DialContext,
			TLSHandshakeTimeout:   requestTimeout,
			ResponseHeaderTimeout: requestTimeout,
			IdleConnTimeout:       requestTimeout,
		}
	}
	return &boundedClient{client: &http.Client{
		Transport:     transport,
		Timeout:       requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Bound all response bodies before SDK decoding, including AWS error responses
// and credential-chain HTTP responses, not just the returned identity token.
func (c *boundedClient) Do(req *http.Request) (*http.Response, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, errors.New("provider redirects are disabled")
	}
	b, err := readBounded(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return resp, nil
}

func (s source) gcp(ctx context.Context, cfg Config) (string, error) {
	const endpoint = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
	query := url.Values{"audience": {cfg.Audience}, "format": {"full"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+query.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Metadata-Flavor") != "Google" {
		return "", errors.New("expected Google identity metadata response")
	}
	b, err := readBounded(resp.Body)
	return string(b), err
}
