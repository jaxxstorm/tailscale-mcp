package workloadidentity

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type newSTSFunc func(aws.Config) stsClient
type loadAWSFunc func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error)
type regionFunc func(context.Context, aws.Config) (string, error)
type stsClient interface {
	GetWebIdentityToken(context.Context, *sts.GetWebIdentityTokenInput, ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error)
}

func (s source) aws(ctx context.Context, cfg Config) (string, error) {
	load := s.loadAWS
	if load == nil {
		load = config.LoadDefaultConfig
	}
	client := acquisitionClient{ctx: ctx, client: s.httpClient}
	opts := []func(*config.LoadOptions) error{config.WithHTTPClient(client), config.WithRetryMaxAttempts(3)}
	if cfg.Region != "" {
		opts = append(opts, config.WithRegion(cfg.Region))
	}
	loaded, err := load(ctx, opts...)
	if err != nil {
		return "", safeError(ctx, "AWS configuration loading failed", err)
	}
	if cfg.Region != "" {
		loaded.Region = cfg.Region
	}
	if strings.TrimSpace(loaded.Region) == "" {
		region := s.awsRegion
		if region == nil {
			region = func(ctx context.Context, c aws.Config) (string, error) {
				out, err := imds.NewFromConfig(c).GetRegion(ctx, &imds.GetRegionInput{})
				if err != nil {
					return "", err
				}
				return out.Region, nil
			}
		}
		loaded.Region, err = region(ctx, loaded)
		if err != nil {
			return "", safeError(ctx, "AWS region discovery failed; configure region", err)
		}
	}
	if strings.TrimSpace(loaded.Region) == "" {
		return "", errors.New("AWS region is required")
	}
	newSTS := s.newSTS
	if newSTS == nil {
		newSTS = func(c aws.Config) stsClient { return sts.NewFromConfig(c) }
	}
	out, err := newSTS(loaded).GetWebIdentityToken(ctx, &sts.GetWebIdentityTokenInput{
		Audience: []string{cfg.Audience}, SigningAlgorithm: aws.String("ES384"), DurationSeconds: aws.Int32(300),
	})
	if err != nil {
		return "", safeError(ctx, "AWS identity issuance failed; check credentials and sts:GetWebIdentityToken permission", err)
	}
	if out == nil || out.WebIdentityToken == nil {
		return "", errors.New("AWS returned no identity token")
	}
	return *out.WebIdentityToken, nil
}
