// Package aws implements the CloudProvider interface for Amazon Web Services.
package aws

import (
	"context"

	"argus/cloud-scanner/internal/providers"
)

// Provider wraps the AWS SDK clients and implements providers.CloudProvider.
type Provider struct {
	roleARN string
	// initialClient is used for identity + region discovery (always us-east-1)
	initialClient *Client
	initialScanner *Scanner
}

// NewProvider initialises the AWS provider. roleARN may be empty for same-account scanning.
func NewProvider(ctx context.Context, roleARN string) (*Provider, error) {
	client, err := New(ctx, "us-east-1", roleARN)
	if err != nil {
		return nil, err
	}
	return &Provider{
		roleARN:        roleARN,
		initialClient:  client,
		initialScanner: NewScanner(client),
	}, nil
}

func (p *Provider) Name() string { return "AWS" }

func (p *Provider) AccountID(ctx context.Context) (string, error) {
	accountID, _, err := p.initialScanner.GetIdentity(ctx)
	return accountID, err
}

func (p *Provider) Regions(ctx context.Context, allRegions bool) ([]string, error) {
	if !allRegions {
		return []string{"us-east-1"}, nil
	}
	return p.initialScanner.GetEnabledRegions(ctx)
}

func (p *Provider) ScanRegion(ctx context.Context, region string) ([]providers.Asset, error) {
	client, err := New(ctx, region, p.roleARN)
	if err != nil {
		return nil, err
	}
	sc := NewScanner(client)

	var assets []providers.Asset

	ec2, err := sc.ScanEC2(ctx, region)
	if err == nil {
		assets = append(assets, toProviderAssets(ec2)...)
	}

	accountID, _, _ := p.initialScanner.GetIdentity(ctx)
	eks, err := sc.ScanEKS(ctx, accountID, region)
	if err == nil {
		assets = append(assets, toProviderAssets(eks)...)
	}

	vpcs, err := sc.ScanVPCs(ctx, region)
	if err == nil {
		assets = append(assets, toProviderAssets(vpcs)...)
	}

	return assets, nil
}

func (p *Provider) ScanGlobal(ctx context.Context) ([]providers.Asset, error) {
	accountID, _, err := p.initialScanner.GetIdentity(ctx)
	if err != nil {
		return nil, err
	}
	iam, err := p.initialScanner.ScanIAM(ctx, accountID)
	if err != nil {
		return nil, err
	}
	return toProviderAssets(iam), nil
}

func toProviderAssets(in []Asset) []providers.Asset {
	out := make([]providers.Asset, len(in))
	for i, a := range in {
		out[i] = providers.Asset{
			ID:        a.ID,
			Type:      a.Type,
			Region:    a.Region,
			AccountID: a.AccountID,
			VpcID:     a.VpcID,
			Details:   a.Details,
		}
	}
	return out
}
