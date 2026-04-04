package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Client struct {
	EC2 *ec2.Client
	IAM *iam.Client
	STS *sts.Client
	EKS *eks.Client
}

func New(ctx context.Context, region string, roleARN string) (*Client, error) {
	// 1. Load default config (Env vars, ~/.aws/credentials)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %v", err)
	}

	// 2. If RoleARN is provided, Assume Role
	if roleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		creds := stscreds.NewAssumeRoleProvider(stsClient, roleARN)
		cfg.Credentials = aws.NewCredentialsCache(creds)
	}

	return &Client{
		EC2: ec2.NewFromConfig(cfg),
		IAM: iam.NewFromConfig(cfg),
		STS: sts.NewFromConfig(cfg),
		EKS: eks.NewFromConfig(cfg),
	}, nil
}
