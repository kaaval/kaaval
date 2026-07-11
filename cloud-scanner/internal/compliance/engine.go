package compliance

import (
	"fmt"

	"kaaval/cloud-scanner/internal/providers/aws"
)

// Severity levels
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// Result represents the outcome of a compliance check
type Result struct {
	CheckID     string
	Description string
	Severity    string
	Status      string // PASS / FAIL
	Details     string
	Remediation string
}

// CheckFunc is the signature for a compliance check function
type CheckFunc func(asset scanner.Asset) *Result

// Registry holds all registered checks
var Registry = map[string]CheckFunc{}

// RegisterCheck adds a check to the registry
func RegisterCheck(id string, fn CheckFunc) {
	Registry[id] = fn
}

// CheckResult holds all results for a specific asset
type AssetCompliance struct {
	AssetID string
	Results []Result
}

// Evaluate runs all registered checks against the provided assets
func Evaluate(assets []scanner.Asset) map[string][]Result {
	fmt.Println("DEBUG: Starting Compliance Evaluation...")
	complianceReport := make(map[string][]Result)

	for _, asset := range assets {
		var results []Result

		// Run Dynamic Checks
		for _, rule := range DynamicChecks {
			res := EvaluateDynamicRule(asset, rule)
			if res != nil {
				results = append(results, *res)
			}
		}

		for id, checkFn := range Registry {
			// Run the check
			res := checkFn(asset)

			// If the check returns a result (meaning it was applicable and ran)
			if res != nil {
				res.CheckID = id // Ensure ID is set
				results = append(results, *res)
			}
		}

		if len(results) > 0 {
			complianceReport[asset.ID] = results
		}
	}

	return complianceReport
}
