package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/google/uuid"

	"argus/cloud-scanner/internal/compliance"
	"argus/cloud-scanner/internal/database"
	"argus/cloud-scanner/internal/providers"
	"argus/cloud-scanner/internal/providers/aws"
)

func main() {
	log.Println("Starting Argus Cloud Scanner...")

	ctx := context.TODO()

	dbConnStr := os.Getenv("DATABASE_URL")
	if dbConnStr == "" {
		dbConnStr = "postgres://argus:password@127.0.0.1:5432/argus_db?sslmode=disable"
	}
	db, err := database.New(dbConnStr)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	roleARN := flag.String("role-arn", "", "IAM Role ARN for cross-account scanning")
	allRegions := flag.Bool("all-regions", false, "Scan all enabled regions")
	flag.Parse()

	extDir := os.Getenv("EXTENSIONS_DIR")
	if extDir == "" {
		extDir = "./extensions/integrations"
	}
	if err := compliance.LoadDynamicRules(extDir); err != nil {
		log.Printf("Warning: failed to load dynamic rules from %s: %v", extDir, err)
	}

	// Resolve scan ID — API passes ARGUS_SCAN_ID so both sides share the same UUID
	var scanID string
	if envID := os.Getenv("ARGUS_SCAN_ID"); envID != "" {
		scanID = envID
		log.Printf("Using API-provided scan ID: %s", scanID)
		db.UpdateScanStatus(ctx, scanID, "IN_PROGRESS", "")
	} else {
		scanID = uuid.New().String()
		log.Printf("Generated scan ID: %s", scanID)
	}

	// Build AWS provider (the only one in v1)
	provider, err := aws.NewProvider(ctx, *roleARN)
	if err != nil {
		log.Fatalf("Failed to init AWS provider: %v", err)
	}

	accountID, err := provider.AccountID(ctx)
	if err != nil {
		log.Fatalf("Failed to get account ID: %v", err)
	}
	log.Printf("Connected to AWS account: %s", accountID)

	if scanID == os.Getenv("ARGUS_SCAN_ID") {
		// status already set to IN_PROGRESS above
	} else {
		if err := db.SaveScan(ctx, scanID, "IN_PROGRESS", accountID); err != nil {
			log.Fatalf("Failed to create scan record: %v", err)
		}
	}

	regions, err := provider.Regions(ctx, *allRegions)
	if err != nil {
		log.Printf("Region discovery failed, defaulting to us-east-1: %v", err)
		regions = []string{"us-east-1"}
	}
	log.Printf("Scanning %d region(s): %v", len(regions), regions)

	var allAssets []providers.Asset

	for _, region := range regions {
		log.Printf("Scanning region: %s", region)
		assets, err := provider.ScanRegion(ctx, region)
		if err != nil {
			log.Printf("[%s] scan error: %v", region, err)
			continue
		}
		log.Printf("[%s] discovered %d assets", region, len(assets))
		allAssets = append(allAssets, assets...)
	}

	globalAssets, err := provider.ScanGlobal(ctx)
	if err != nil {
		log.Printf("Global scan error: %v", err)
	} else {
		log.Printf("Global: discovered %d assets", len(globalAssets))
		allAssets = append(allAssets, globalAssets...)
	}

	// Run compliance engine
	complianceResults := compliance.Evaluate(toScannerAssets(allAssets))

	// Persist assets
	log.Printf("Saving %d assets...", len(allAssets))
	for _, asset := range allAssets {
		var detailsMap map[string]interface{}
		if len(asset.Details) > 0 {
			_ = json.Unmarshal(asset.Details, &detailsMap)
		} else {
			detailsMap = make(map[string]interface{})
		}
		if results, ok := complianceResults[asset.ID]; ok {
			detailsMap["compliance"] = results
		}
		asset.Details, _ = json.Marshal(detailsMap)

		if err := db.SaveAsset(ctx, scanID, toDBAsset(asset)); err != nil {
			log.Printf("Failed to save asset %s: %v", asset.ID, err)
		}
	}

	db.UpdateScanStatus(ctx, scanID, "COMPLETED", "")
	log.Printf("Scan %s completed — %d assets discovered", scanID, len(allAssets))
}

// toScannerAssets converts the canonical providers.Asset slice to the type expected by the compliance engine.
// This thin shim avoids circular imports between providers and compliance packages.
func toScannerAssets(in []providers.Asset) []compliance.Asset {
	out := make([]compliance.Asset, len(in))
	for i, a := range in {
		out[i] = compliance.Asset{
			ID:      a.ID,
			Type:    a.Type,
			Details: a.Details,
		}
	}
	return out
}

func toDBAsset(a providers.Asset) database.Asset {
	return database.Asset{
		ID:        a.ID,
		Type:      a.Type,
		Region:    a.Region,
		AccountID: a.AccountID,
		VpcID:     a.VpcID,
		Details:   a.Details,
	}
}
