package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func (s *Scanner) ScanVPCs(ctx context.Context, region string) ([]Asset, error) {
	fmt.Println("DEBUG: Starting VPC Deep Discovery...")
	var assets []Asset

	// 1. Describe VPCs
	vpcsOutput, err := s.client.EC2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe vpcs: %v", err)
	}

	// 2. Describe Subnets (All)
	subnetsOutput, err := s.client.EC2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{})
	if err != nil {
		fmt.Printf("WARN: Failed to describe subnets: %v\n", err)
	}

	// 3. Describe Route Tables (All)
	rtsOutput, err := s.client.EC2.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{})
	if err != nil {
		fmt.Printf("WARN: Failed to describe route tables: %v\n", err)
	}

	// 4. Describe Peering Connections (All)
	peersOutput, err := s.client.EC2.DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{})
	if err != nil {
		fmt.Printf("WARN: Failed to describe peering connections: %v\n", err)
	}

	// Organize data by VPC ID
	// Subnets map
	subnetsByVPC := make(map[string][]interface{})
	if subnetsOutput != nil {
		for _, subnet := range subnetsOutput.Subnets {
			sDetails := map[string]interface{}{
				"SubnetId":            *subnet.SubnetId,
				"CidrBlock":           *subnet.CidrBlock,
				"AvailabilityZone":    *subnet.AvailabilityZone,
				"MapPublicIpOnLaunch": *subnet.MapPublicIpOnLaunch,
				"State":               subnet.State,
			}
			vpcID := *subnet.VpcId
			subnetsByVPC[vpcID] = append(subnetsByVPC[vpcID], sDetails)
		}
	}

	// Route Tables map
	rtsByVPC := make(map[string][]interface{})
	if rtsOutput != nil {
		for _, rt := range rtsOutput.RouteTables {
			var routes []interface{}
			for _, r := range rt.Routes {
				routes = append(routes, map[string]interface{}{
					"DestinationCidrBlock":   r.DestinationCidrBlock,
					"GatewayId":              r.GatewayId,
					"NatGatewayId":           r.NatGatewayId,
					"VpcPeeringConnectionId": r.VpcPeeringConnectionId,
					"State":                  r.State,
				})
			}
			rtDetails := map[string]interface{}{
				"RouteTableId": *rt.RouteTableId,
				"Routes":       routes,
				"Main":         false, // TODO check associations
			}
			vpcID := *rt.VpcId
			rtsByVPC[vpcID] = append(rtsByVPC[vpcID], rtDetails)
		}
	}

	// Peering map (Check both Requester and Accepter)
	peersByVPC := make(map[string][]interface{})
	if peersOutput != nil {
		for _, peer := range peersOutput.VpcPeeringConnections {
			pDetails := map[string]interface{}{
				"VpcPeeringConnectionId": *peer.VpcPeeringConnectionId,
				"Status":                 peer.Status.Code,
				"RequesterVpc":           *peer.RequesterVpcInfo.VpcId,
				"AccepterVpc":            *peer.AccepterVpcInfo.VpcId,
			}

			// Associate with BOTH VPCs if they are in this account (simplified logic: just add to map keys)
			if peer.RequesterVpcInfo != nil && peer.RequesterVpcInfo.VpcId != nil {
				peersByVPC[*peer.RequesterVpcInfo.VpcId] = append(peersByVPC[*peer.RequesterVpcInfo.VpcId], pDetails)
			}
			if peer.AccepterVpcInfo != nil && peer.AccepterVpcInfo.VpcId != nil {
				peersByVPC[*peer.AccepterVpcInfo.VpcId] = append(peersByVPC[*peer.AccepterVpcInfo.VpcId], pDetails)
			}
		}
	}

	// Assemble Assets
	for _, vpc := range vpcsOutput.Vpcs {
		vpcID := *vpc.VpcId

		detailsMap := map[string]interface{}{
			"VpcId":       vpcID,
			"CidrBlock":   *vpc.CidrBlock,
			"State":       vpc.State,
			"IsDefault":   vpc.IsDefault,
			"Tags":        vpc.Tags,
			"Subnets":     subnetsByVPC[vpcID],
			"RouteTables": rtsByVPC[vpcID],
			"Peerings":    peersByVPC[vpcID],
		}

		detailsBytes, _ := json.Marshal(detailsMap)

		assets = append(assets, Asset{
			ID:        vpcID,
			Type:      "VPC",
			Region:    region,
			AccountID: *vpc.OwnerId,
			VpcID:     vpcID,
			Details:   detailsBytes,
		})
	}

	fmt.Printf("DEBUG: Discovered %d VPCs.\n", len(assets))
	return assets, nil
}
