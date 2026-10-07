// Package workloadidentity acquires explicitly selected workload assertions.
// Local JWT checks are sanity checks, not signature or authorization validation.
package workloadidentity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

const (
	maxSize            = 1 << 20
	acquisitionTimeout = 30 * time.Second
	requestTimeout     = 5 * time.Second
	defaultTokenFile   = "/var/run/secrets/tailscale/token"
)

// Config selects exactly one provider. Empty TokenFile and Region select defaults.
// JSON parsing must distinguish absent fields from explicitly empty fields.
type Config struct {
	Provider, Audience, TokenFile, Region string
}

// Validate checks configuration without performing provider I/O.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Audience) == "" {
		return errors.New("workload identity requires a nonblank audience")
	}
	switch c.Provider {
	case "kubernetes", "aws", "gcp":
	default:
		return errors.New("workload identity provider must be kubernetes, aws, or gcp")
	}
	if c.TokenFile != "" && (c.Provider != "kubernetes" || strings.TrimSpace(c.TokenFile) == "") {
		return errors.New("tokenFile must be a nonblank Kubernetes-only setting")
	}
	if c.Region != "" && (c.Provider != "aws" || strings.TrimSpace(c.Region) == "") {
		return errors.New("region must be a nonblank AWS-only setting")
	}
	return nil
}

// Acquire obtains a fresh assertion with a maximum 30-second budget. Kubernetes
// files must reside on a local projected volume: regular-file I/O is not cancellable.
func Acquire(ctx context.Context, cfg Config) (string, error) {
	return source{}.acquire(ctx, cfg)
}

type source struct {
	httpClient httpDoer
	loadAWS    loadAWSFunc
	awsRegion  regionFunc
	newSTS     newSTSFunc
	now        func() time.Time
}

func (s source) acquire(ctx context.Context, cfg Config) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, acquisitionTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.httpClient == nil {
		client := newHTTPClient(nil)
		defer client.client.CloseIdleConnections()
		s.httpClient = client
	}
	var token string
	var err error
	switch cfg.Provider {
	case "kubernetes":
		token, err = readToken(ctx, cfg.TokenFile)
		if err != nil {
			err = safeError(ctx, "kubernetes projected-token read failed; check tokenFile and volume permissions", err)
		}
	case "aws":
		token, err = s.aws(ctx, cfg)
	case "gcp":
		token, err = s.gcp(ctx, cfg)
		if err != nil {
			err = safeError(ctx, "gcp identity metadata acquisition failed; check attached service account and metadata access", err)
		}
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		return "", fmt.Errorf("%s assertion acquisition failed: %w", cfg.Provider, err)
	}
	token, err = validateToken(token, cfg.Audience, s.now())
	if err != nil {
		return "", fmt.Errorf("%s assertion rejected: %w", cfg.Provider, err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return token, nil
}

func safeError(ctx context.Context, stage string, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%s: %w", stage, ctx.Err())
	}
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, sentinel) {
			return fmt.Errorf("%s: %w", stage, sentinel)
		}
	}
	return errors.New(stage)
}

func readBounded(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSize {
		return nil, errors.New("assertion response exceeds 1 MiB")
	}
	return b, nil
}

func validateToken(token, audience string, now time.Time) (string, error) {
	invalid := errors.New("expected a compact JWT with a future expiration and matching audience")
	if len(token) > maxSize {
		return "", errors.New("assertion exceeds 1 MiB")
	}
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", invalid
	}
	decoded := make([][]byte, 3)
	for i, part := range parts {
		if part == "" || strings.ContainsAny(part, "\r\n") {
			return "", invalid
		}
		var err error
		decoded[i], err = base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || len(decoded[i]) == 0 {
			return "", invalid
		}
	}
	var header struct {
		Alg string `json:"alg"`
	}
	var claims map[string]any
	if json.Unmarshal(decoded[0], &header) != nil || strings.TrimSpace(header.Alg) == "" || strings.EqualFold(header.Alg, "none") || json.Unmarshal(decoded[1], &claims) != nil {
		return "", invalid
	}
	exp, ok := claims["exp"].(float64)
	if !ok || math.IsInf(exp, 0) || math.IsNaN(exp) || exp <= float64(now.Unix())+float64(now.Nanosecond())/1e9 {
		return "", invalid
	}
	match := false
	switch aud := claims["aud"].(type) {
	case string:
		match = aud == audience
	case []any:
		for _, value := range aud {
			text, ok := value.(string)
			if !ok {
				return "", invalid
			}
			match = match || text == audience
		}
	}
	if !match {
		return "", invalid
	}
	return token, nil
}
