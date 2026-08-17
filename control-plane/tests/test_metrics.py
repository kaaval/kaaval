"""
Real test of the /metrics collector, against an in-memory SQLite DB rather
than the Postgres instance test_smoke.py needs — no Docker required.

Covers both layers Codex's independent review flagged as untested:
collect_metrics() directly, AND the real /metrics HTTP route end-to-end
(status code, content-type, dependency injection through database.get_db).
"""

import os
import uuid

os.environ.setdefault("KAAVAL_ADMIN_PASSWORD", "test-admin-password")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import database, models
from app.metrics import CONTENT_TYPE_LATEST, collect_metrics

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000000")


def _session(threadsafe: bool = False):
    # threadsafe=True: needed by the real /metrics route test — FastAPI runs
    # sync route handlers in a threadpool. Two real, separate SQLite gotchas
    # confirmed by actually hitting them, not assumed upfront:
    #   1. check_same_thread=False — SQLite connections are thread-affine by
    #      default (hit a real sqlite3.ProgrammingError without this).
    #   2. poolclass=StaticPool — sqlite:///:memory: gives each new physical
    #      connection its own separate, empty database by default; without
    #      forcing a single shared connection, the threadpool-executed
    #      request hit a blank DB with no tables (hit a real "no such table"
    #      error without this).
    if threadsafe:
        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    else:
        engine = create_engine("sqlite:///:memory:")
    models.Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def test_metrics_is_valid_prometheus_exposition_format():
    db = _session()
    body = collect_metrics(db).decode()
    # No data yet, but the exposition format itself must still be well-formed:
    # every non-comment line is "metric_name{labels} value".
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        assert " " in line, f"malformed exposition line: {line!r}"


def test_scan_status_appears_as_a_kaaval_specific_metric():
    db = _session()
    db.add(models.Tenant(id=TENANT_ID, name="Default"))
    db.commit()
    db.add(models.Scan(id=uuid.uuid4(), tenant_id=TENANT_ID, status="COMPLETED"))
    db.add(models.Scan(id=uuid.uuid4(), tenant_id=TENANT_ID, status="COMPLETED"))
    db.add(models.Scan(id=uuid.uuid4(), tenant_id=TENANT_ID, status="FAILED"))
    db.commit()

    body = collect_metrics(db).decode()
    assert 'kaaval_scans_total{status="COMPLETED"} 2.0' in body
    assert 'kaaval_scans_total{status="FAILED"} 1.0' in body


def test_vulnerability_severity_appears_as_a_kaaval_specific_metric():
    db = _session()
    db.add(models.Vulnerability(
        id="CVE-2026-0001", source="NVD", severity="CRITICAL",
    ))
    db.commit()

    body = collect_metrics(db).decode()
    assert 'kaaval_vulnerabilities_total{severity="CRITICAL"} 1.0' in body


def test_asset_vulnerability_and_integration_finding_metrics():
    db = _session()
    db.add(models.Tenant(id=TENANT_ID, name="Default"))
    db.commit()
    db.add(models.Vulnerability(id="CVE-2026-0002", source="OSV", severity="HIGH"))
    db.commit()
    db.add(models.AssetVulnerability(
        id=uuid.uuid4(), vulnerability_id="CVE-2026-0002", asset_id="asset-1",
        asset_type="host", scan_id=uuid.uuid4(), status="Active",
    ))
    db.commit()
    integration_id = uuid.uuid4()
    db.add(models.IntegrationConfig(
        id=integration_id, tenant_id=TENANT_ID, plugin_id="wazuh", name="wazuh-prod",
    ))
    db.commit()
    db.add(models.IntegrationFinding(
        id=uuid.uuid4(), tenant_id=TENANT_ID, integration_id=integration_id,
        source_tool="wazuh", finding_type="alert", severity="HIGH",
        title="Test finding", status="open",
    ))
    db.commit()

    body = collect_metrics(db).decode()
    assert 'kaaval_asset_vulnerabilities_total{status="Active"} 1.0' in body
    assert 'kaaval_integration_findings_total{severity="HIGH",status="open"} 1.0' in body


def test_metrics_route_returns_prometheus_content_type_and_real_data():
    """End-to-end: the real /metrics HTTP route, not just the collector function —
    the exact gap flagged by independent review."""
    db = _session(threadsafe=True)
    db.add(models.Endpoint(
        id=uuid.uuid4(), tenant_id=TENANT_ID, hostname="host-1", status="ONLINE",
    ))
    db.commit()

    def override_get_db():
        try:
            yield db
        finally:
            pass

    from app.main import app
    app.dependency_overrides[database.get_db] = override_get_db
    try:
        # Plain TestClient(app), not `with TestClient(app) as client:` — the
        # context-manager form fires the app's startup event, which connects
        # to real Postgres directly (bypassing dependency_overrides, which
        # only patches Depends()-injected params). This route needs none of
        # that startup work, so skip it rather than fight it.
        client = TestClient(app)
        resp = client.get("/metrics")
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith(CONTENT_TYPE_LATEST.split(";")[0])
    assert 'kaaval_endpoints_total{status="ONLINE"} 1.0' in resp.text
