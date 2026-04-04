package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"argus/cloud-scanner/internal/providers/aws"

	_ "github.com/lib/pq"
)

// Hardcoded for Prototype
const DefaultTenantID = "00000000-0000-0000-0000-000000000000"

type DB struct {
	conn *sql.DB
}

func New(connStr string) (*DB, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &DB{conn: db}, nil
}

func (d *DB) Close() error {
	return d.conn.Close()
}

func (d *DB) CreateScan(ctx context.Context, region string) string {
	var id string
	query := `INSERT INTO scans (status, region) VALUES ($1, $2) RETURNING id`
	err := d.conn.QueryRowContext(ctx, query, "RUNNING", region).Scan(&id)
	if err != nil {
		// Log error but allow continuation? For prototype, returning empty is simple signal
		fmt.Printf("Error creating scan: %v\n", err)
		return ""
	}
	return id
}

func (d *DB) UpdateScanStatus(ctx context.Context, id, status, errMsg string) {
	if id == "" {
		return
	}
	query := `UPDATE scans SET status = $1, error_message = $2, completed_at = $3 WHERE id = $4`
	timestamp := time.Now()
	if status == "RUNNING" {
		// Just status update
		query = `UPDATE scans SET status = $1, error_message = $2 WHERE id = $3`
		_, _ = d.conn.ExecContext(ctx, query, status, errMsg, id)
	} else {
		// Completion
		_, _ = d.conn.ExecContext(ctx, query, status, errMsg, timestamp, id)
	}
}

func (db *DB) SaveScan(ctx context.Context, scanID string, status string, accountID string) error {
	query := `INSERT INTO scans (id, tenant_id, status, account_id, started_at) VALUES ($1, $2, $3, $4, NOW())`
	_, err := db.conn.ExecContext(ctx, query, scanID, DefaultTenantID, status, accountID)
	return err
}

func (d *DB) SaveAsset(ctx context.Context, scanID string, asset scanner.Asset) error {
	if scanID == "" {
		return fmt.Errorf("invalid scan id")
	}
	query := `
        INSERT INTO assets (id, tenant_id, scan_id, asset_type, region, account_id, vpc_id, details, first_seen, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        ON CONFLICT (id, asset_type, scan_id) DO UPDATE 
        SET last_seen = NOW(), details = $8
    `
	_, err := d.conn.ExecContext(ctx, query,
		asset.ID,
		DefaultTenantID,
		scanID,
		asset.Type,
		asset.Region,
		asset.AccountID,
		asset.VpcID,
		asset.Details,
	)
	return err
}
