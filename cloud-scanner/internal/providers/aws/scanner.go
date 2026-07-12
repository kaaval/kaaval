package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"kaaval/cloud-scanner/internal/providers/aws"

	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"kaaval/cloud-scanner/internal/providers/aws"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Asset struct {
	ID        string
	Type      string
	Region    string
	AccountID string
	VpcID     string
	Details   json.RawMessage
}

type Scanner struct {
	client *aws_client.Client
}

func New(client *aws_client.Client) *Scanner {
	return &Scanner{client: client}
}

func (s *Scanner) GetEnabledRegions(ctx context.Context) ([]string, error) {
	// 1. Describe Regions
	// We default to "AllRegions=false" (default in AWS API) which returns only enabled regions.
	// To get disabled ones too, we'd need AllRegions=true.
	// The user request "active on..." implies enabled regions.
	output, err := s.client.EC2.DescribeRegions(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to describe regions: %v", err)
	}

	var regions []string
	for _, r := range output.Regions {
		regions = append(regions, *r.RegionName)
	}
	return regions, nil
}

func (s *Scanner) ScanEC2(ctx context.Context, region string) ([]Asset, error) {
	var assets []Asset

	// Describe Instances
	output, err := s.client.EC2.DescribeInstances(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %v", err)
	}

	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			details, _ := json.Marshal(instance)

			// Best effort to get Account ID
			accountID := *reservation.OwnerId

			assets = append(assets, Asset{
				ID:        *instance.InstanceId,
				Type:      "EC2",
				Region:    region,
				AccountID: accountID,
				VpcID:     awsString(instance.VpcId),
				Details:   details,
			})
		}
	}

	return assets, nil
}

func (s *Scanner) GetIdentity(ctx context.Context) (string, string, error) {
	input := &sts.GetCallerIdentityInput{}
	output, err := s.client.STS.GetCallerIdentity(ctx, input)
	if err != nil {
		return "", "", fmt.Errorf("failed to get caller identity: %v", err)
	}
	return *output.Account, *output.Arn, nil
}

func (s *Scanner) ScanIAM(ctx context.Context, accountID string) ([]Asset, error) {
	var assets []Asset

	// Debug: Print that we are starting
	fmt.Println("DEBUG: Starting IAM ListUsers call...")

	// List Users
	output, err := s.client.IAM.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list iam users: %v", err)
	}

	fmt.Printf("DEBUG: API returned %d users.\n", len(output.Users))

	for _, user := range output.Users {
		userDetails := map[string]interface{}{
			"User": user,
			"Keys": []map[string]interface{}{},
		}

		// List Access Keys for User
		keysOutput, err := s.client.IAM.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: user.UserName,
		})
		if err == nil {
			for _, key := range keysOutput.AccessKeyMetadata {
				userDetails["Keys"] = append(userDetails["Keys"].([]map[string]interface{}), map[string]interface{}{
					"AccessKeyId": *key.AccessKeyId,
					"Status":      key.Status, // Active / Inactive
					"CreatedDate": key.CreateDate,
				})
			}
		}

		detailsBytes, _ := json.Marshal(userDetails)

		assets = append(assets, Asset{
			ID:        *user.UserName,
			Type:      "IAM_USER",
			Region:    "global",
			AccountID: accountID,
			VpcID:     "",
			Details:   detailsBytes,
		})
	}
	return assets, nil
}

func awsString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (s *Scanner) ScanEKS(ctx context.Context, accountID string, region string) ([]Asset, error) {
	var assets []Asset

	// List Clusters
	output, err := s.client.EKS.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list eks clusters: %v", err)
	}

	fmt.Printf("DEBUG: Found %d EKS clusters.\n", len(output.Clusters))

	for _, clusterName := range output.Clusters {
		// Describe Cluster to get details
		descOutput, err := s.client.EKS.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: &clusterName,
		})

		var detailsBytes []byte

		if err == nil && descOutput.Cluster != nil {
			cluster := descOutput.Cluster
			endpoint := *cluster.Endpoint

			// Deep Discovery: List Namespaces
			var namespaces []string
			// TODO: Use CA data from cluster.CertificateAuthority.Data

			// Initialize K8s Client
			k8sClient, k8sErr := eks_client.NewClientset(ctx, s.client.STS, clusterName, endpoint, "")
			if k8sErr != nil {
				fmt.Printf("WARN: Failed to connect to cluster %s: %v\n", clusterName, k8sErr)
				namespaces = []string{"Error: Connection Failed"}
			} else {
				// Fetch Namespaces
				nsList, nsErr := k8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
				if nsErr != nil {
					fmt.Printf("WARN: Failed to list namespaces for %s: %v\n", clusterName, nsErr)
					namespaces = []string{fmt.Sprintf("Error: %v", nsErr)}
				} else {
					for _, ns := range nsList.Items {
						namespaces = append(namespaces, ns.Name)
					}
					fmt.Printf("DEBUG: Discovered %d namespaces in %s\n", len(namespaces), clusterName)
				}
			}

			// 3. Image Security: Extract Container Images
			uniqueImages := make(map[string]bool)
			var imageList []string

			// List all Pods in all namespaces
			podList, podErr := k8sClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
			if podErr != nil {
				fmt.Printf("WARN: Failed to list pods for %s: %v\n", clusterName, podErr)
			} else {
				for _, pod := range podList.Items {
					for _, container := range pod.Spec.Containers {
						uniqueImages[container.Image] = true
					}
					// Also check InitContainers
					for _, container := range pod.Spec.InitContainers {
						uniqueImages[container.Image] = true
					}
				}

				// Convert map to slice
				for img := range uniqueImages {
					imageList = append(imageList, img)
				}
				fmt.Printf("DEBUG: Found %d unique images in %s\n", len(imageList), clusterName)
			}

			detailsMap := map[string]interface{}{
				"Version":    cluster.Version,
				"Status":     cluster.Status,
				"Endpoint":   cluster.Endpoint,
				"Arn":        cluster.Arn,
				"Namespaces": namespaces,
				"Images":     imageList,
			}
			detailsBytes, _ = json.Marshal(detailsMap)
		} else {
			detailsBytes = []byte("{}")
		}

		assets = append(assets, Asset{
			ID:        clusterName,
			Type:      "EKS_CLUSTER",
			Region:    region,
			AccountID: accountID,
			VpcID:     "", // Could extract from subnets if needed
			Details:   detailsBytes,
		})
	}

	return assets, nil
}
