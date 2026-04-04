// Package providers defines the CloudProvider interface and the Asset type
// shared across all cloud provider implementations.
package providers

import "context"

// Asset is the canonical representation of any discovered cloud resource.
type Asset struct {
	ID        string
	Type      string // EC2 | IAM_USER | S3_BUCKET | EKS_CLUSTER | VPC | ...
	Region    string
	AccountID string
	VpcID     string
	Details   []byte // JSON blob with provider-specific fields
}

// CloudProvider is implemented by each cloud provider (AWS, DigitalOcean, GCP, …).
// Add a new provider by implementing this interface and registering it in cmd/scanner/main.go.
type CloudProvider interface {
	// Name returns a human-readable provider name (e.g. "AWS", "DigitalOcean").
	Name() string

	// AccountID returns the cloud account/project identifier.
	AccountID(ctx context.Context) (string, error)

	// Regions returns the list of regions to scan. If allRegions is false,
	// implementations should return only the default/home region.
	Regions(ctx context.Context, allRegions bool) ([]string, error)

	// ScanRegion discovers all assets in the given region.
	ScanRegion(ctx context.Context, region string) ([]Asset, error)

	// ScanGlobal discovers global (non-regional) resources such as IAM.
	ScanGlobal(ctx context.Context) ([]Asset, error)
}
