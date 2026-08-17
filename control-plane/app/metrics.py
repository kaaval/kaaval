"""
Prometheus /metrics surface.

Real-time gauges computed on every scrape (a fresh query, not a cached
counter), so a value always reflects the current state of the database
rather than drifting from process-lifetime counters. Kept dependency-light:
one SQL statement per metric family, same session pattern as health.py.
"""

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest
from sqlalchemy import func
from sqlalchemy.orm import Session

from . import models


def collect_metrics(db: Session) -> bytes:
    """Query the current state and render it as Prometheus exposition format."""
    registry = CollectorRegistry()

    scans_by_status = Gauge(
        "kaaval_scans_total", "Scans by status", ["status"], registry=registry
    )
    for status, count in db.query(models.Scan.status, func.count(models.Scan.id)).group_by(
        models.Scan.status
    ).all():
        scans_by_status.labels(status=status or "unknown").set(count)

    vulns_by_severity = Gauge(
        "kaaval_vulnerabilities_total", "Known vulnerabilities by severity", ["severity"],
        registry=registry,
    )
    for severity, count in db.query(
        models.Vulnerability.severity, func.count(models.Vulnerability.id)
    ).group_by(models.Vulnerability.severity).all():
        vulns_by_severity.labels(severity=severity or "UNKNOWN").set(count)

    asset_vulns_by_status = Gauge(
        "kaaval_asset_vulnerabilities_total",
        "Asset-vulnerability links by remediation status", ["status"],
        registry=registry,
    )
    for status, count in db.query(
        models.AssetVulnerability.status, func.count(models.AssetVulnerability.id)
    ).group_by(models.AssetVulnerability.status).all():
        asset_vulns_by_status.labels(status=status or "unknown").set(count)

    integration_findings = Gauge(
        "kaaval_integration_findings_total",
        "Integration findings by severity and status", ["severity", "status"],
        registry=registry,
    )
    for severity, status, count in db.query(
        models.IntegrationFinding.severity,
        models.IntegrationFinding.status,
        func.count(models.IntegrationFinding.id),
    ).group_by(models.IntegrationFinding.severity, models.IntegrationFinding.status).all():
        integration_findings.labels(
            severity=severity or "UNKNOWN", status=status or "unknown"
        ).set(count)

    rbac_scan_results = Gauge(
        "kaaval_rbac_scan_results_total", "RBAC scan results by status", ["status"],
        registry=registry,
    )
    for status, count in db.query(
        models.RBACScanResult.status, func.count(models.RBACScanResult.id)
    ).group_by(models.RBACScanResult.status).all():
        rbac_scan_results.labels(status=status or "unknown").set(count)

    endpoints_by_status = Gauge(
        "kaaval_endpoints_total", "Registered endpoints by status", ["status"],
        registry=registry,
    )
    for status, count in db.query(
        models.Endpoint.status, func.count(models.Endpoint.id)
    ).group_by(models.Endpoint.status).all():
        endpoints_by_status.labels(status=status or "unknown").set(count)

    return generate_latest(registry)
