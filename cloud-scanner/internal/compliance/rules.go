package compliance

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"argus/cloud-scanner/internal/providers/aws"

	"gopkg.in/yaml.v3"
)

// ...

// DynamicIntegration represents the structure of the YAML file
type DynamicIntegration struct {
	Meta   IntegrationMeta `yaml:"meta"`
	Checks []DynamicRule   `yaml:"checks"`
}

type IntegrationMeta struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
}

type DynamicRule struct {
	ID              string        `yaml:"id"`
	Name            string        `yaml:"name"`
	Description     string        `yaml:"description"`
	Severity        string        `yaml:"severity"`
	TargetAssetType string        `yaml:"target_asset_type"`
	Condition       RuleCondition `yaml:"condition"`
	Remediation     string        `yaml:"remediation"`
}

type RuleCondition struct {
	Operator string `yaml:"operator"` // contains, equals, list_none_match
	Field    string `yaml:"field"`    // JSON path field (e.g. details.Images or id)
	Value    string `yaml:"value"`    // Expected value
	Suffix   string `yaml:"suffix"`   // For string suffix checks
	Negate   bool   `yaml:"negate"`   // Invert result
}

var DynamicChecks []DynamicRule

// LoadDynamicRules scans the extensions directory and loads YAML rules
func LoadDynamicRules(extensionsDir string) error {
	files, err := filepath.Glob(filepath.Join(extensionsDir, "*.yaml"))
	if err != nil {
		return err
	}

	DynamicChecks = []DynamicRule{}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			log.Println("Error opening rule file:", file, err)
			continue
		}
		defer f.Close()

		bytes, _ := io.ReadAll(f)
		var integration DynamicIntegration
		if err := yaml.Unmarshal(bytes, &integration); err != nil {
			log.Println("Error parsing YAML:", file, err)
			continue
		}

		// Add rules with prefixes if needed, or raw
		DynamicChecks = append(DynamicChecks, integration.Checks...)
		log.Printf("Loaded %d dynamic checks from %s", len(integration.Checks), integration.Meta.ID)
	}
	return nil
}

// EvaluateDynamicRule runs a single dynamic rule against an asset
func EvaluateDynamicRule(asset scanner.Asset, rule DynamicRule) *Result {
	if asset.Type != rule.TargetAssetType {
		return nil
	}

	// Resolve field value
	fieldValue := resolveField(asset, rule.Condition.Field)

	var matched bool

	switch rule.Condition.Operator {
	case "contains":
		strVal, ok := fieldValue.(string)
		if ok {
			matched = strings.Contains(strings.ToLower(strVal), strings.ToLower(rule.Condition.Value))
		}
	case "equals":
		strVal, ok := fieldValue.(string)
		if ok {
			matched = strings.EqualFold(strVal, rule.Condition.Value)
		}
	case "list_none_match":
		// Ensure NO item in the list matches the suffix/value
		listVal, ok := fieldValue.([]interface{})
		if ok {
			foundMatch := false
			for _, item := range listVal {
				strItem, isStr := item.(string)
				if isStr {
					if rule.Condition.Suffix != "" && strings.HasSuffix(strItem, rule.Condition.Suffix) {
						foundMatch = true
						break
					}
					if rule.Condition.Value != "" && strItem == rule.Condition.Value {
						foundMatch = true
						break
					}
				}
			}
			matched = foundMatch // Condition is "found a bad item"
		}
	}

	// Logic:
	// If Operator is "contains" and we found it -> That's usually a BAD thing (e.g. found "admin")
	// If Negate is true -> We flip.

	// For "contains" "admin": matched=true means we found admin. Status=FAIL.
	// For "list_none_match" suffix ":latest": matched=true means we found :latest. Status=FAIL.

	// So 'matched' == 'violation found' in these simple cases.

	if rule.Condition.Negate {
		matched = !matched
	}

	if matched {
		return &Result{
			CheckID:     rule.ID,
			Description: rule.Name,
			Severity:    rule.Severity,
			Status:      "FAIL",
			Details:     fmt.Sprintf("Condition met: %v", rule.Condition),
			Remediation: rule.Remediation,
		}
	}

	return &Result{
		CheckID:     rule.ID,
		Description: rule.Name,
		Severity:    rule.Severity,
		Status:      "PASS",
		Details:     "Condition not met.",
	}
}

func resolveField(asset scanner.Asset, fieldInfo string) interface{} {
	if fieldInfo == "id" {
		return asset.ID
	}

	// Quick Hack for details.XXX
	if strings.HasPrefix(fieldInfo, "details.") {
		key := strings.TrimPrefix(fieldInfo, "details.")
		var details map[string]interface{}
		_ = json.Unmarshal(asset.Details, &details)
		if val, ok := details[key]; ok {
			return val
		}
	}
	return nil
}
