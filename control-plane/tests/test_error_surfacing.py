"""
Error-surface tests — written before the implementation (G2, tests-first).

Covers the failure modes an operator actually hits:
  - Postgres unreachable          → named check fails with the fix command
  - CVE feed missing/stale        → named check fails with the refresh command
  - no kubeconfig / not in-cluster → named check fails with setup guidance
  - unauthenticated request       → clean 401, no stack
  - unhandled server exception    → 500 with error_id, never the traceback

Bad --manifests paths are covered by tests/test_cli_manifests_errors.py.

Requires a reachable Postgres (same DATABASE_URL contract as test_smoke.py).
"""

import os

os.environ.setdefault("KAAVAL_ADMIN_PASSWORD", "test-admin-password")

from datetime import datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from app import database, models
from app.health import (
    FEED_STALE_AFTER_HOURS,
    check_cve_feeds,
    check_database,
    check_kubernetes,
)
from app.main import app

# The deep-health checks must work on a cold database too, so the test
# module creates the schema itself instead of relying on app startup order.
models.Base.metadata.create_all(bind=database.engine)

DEAD_DB_URL = "postgresql://kaaval:sekrit@127.0.0.1:59999/kaaval_db"


def _dead_engine():
    return create_engine(DEAD_DB_URL, connect_args={"connect_timeout": 1})


# ── Postgres down ──────────────────────────────────────────────────────────────

def test_database_down_reports_fix_command_without_leaking_credentials():
    result = check_database(_dead_engine())
    assert result["ok"] is False
    assert result["required"] is True
    # Actionable: tells the operator exactly how to bring the dependency up
    assert "docker compose" in result["fix"]
    assert "DATABASE_URL" in result["fix"]
    # The connection password must never appear anywhere in the check output
    assert "sekrit" not in str(result)


def test_deep_health_returns_503_when_database_is_down(monkeypatch):
    monkeypatch.setattr(database, "engine", _dead_engine())
    client = TestClient(app)  # no lifespan: startup must not mask the failure
    resp = client.get("/health", params={"deep": 1})
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "error"
    postgres = next(c for c in body["checks"] if c["name"] == "postgres")
    assert postgres["ok"] is False
    assert "docker compose" in postgres["fix"]
    assert "sekrit" not in resp.text


# ── CVE feed missing / stale ───────────────────────────────────────────────────

def test_missing_cve_feeds_reported_with_fix():
    db = database.SessionLocal()
    try:
        db.query(models.CVEFeed).delete()
        db.commit()
        result = check_cve_feeds(db)
        assert result["ok"] is False
        assert "restart" in result["fix"].lower() or "/cve/feeds" in result["fix"]
    finally:
        db.close()


def test_stale_cve_feed_reported_with_refresh_command():
    db = database.SessionLocal()
    try:
        db.query(models.CVEFeed).delete()
        db.commit()
        db.add(models.CVEFeed(
            name="stale-feed",
            url="https://example.invalid/feed.json",
            feed_type="json_feed",
            last_fetched=datetime.utcnow() - timedelta(hours=FEED_STALE_AFTER_HOURS + 1),
        ))
        db.commit()
        result = check_cve_feeds(db)
        assert result["ok"] is False
        assert "stale" in result["detail"].lower()
        assert "/cve/feeds/refresh-all" in result["fix"]
    finally:
        db.query(models.CVEFeed).filter(models.CVEFeed.name == "stale-feed").delete()
        db.commit()
        db.close()


def test_fresh_cve_feed_passes():
    db = database.SessionLocal()
    try:
        db.add(models.CVEFeed(
            name="fresh-feed",
            url="https://example.invalid/fresh.json",
            feed_type="json_feed",
            last_fetched=datetime.utcnow(),
        ))
        db.commit()
        result = check_cve_feeds(db)
        assert result["ok"] is True
    finally:
        db.query(models.CVEFeed).filter(models.CVEFeed.name == "fresh-feed").delete()
        db.commit()
        db.close()


# ── Kubernetes credentials missing ─────────────────────────────────────────────

def test_kubernetes_unconfigured_gives_setup_guidance(monkeypatch):
    from kubernetes import config as k8s_config

    def _no_config(*args, **kwargs):
        raise k8s_config.ConfigException("no config in test")

    monkeypatch.setattr(k8s_config, "load_incluster_config", _no_config)
    monkeypatch.setattr(k8s_config, "load_kube_config", _no_config)

    result = check_kubernetes()
    assert result["ok"] is False
    assert result["required"] is False  # manifest-only scanning still works
    assert "KUBECONFIG" in result["fix"]


# ── Unauthenticated request ────────────────────────────────────────────────────

def test_unauthenticated_request_is_clean_401():
    client = TestClient(app)
    resp = client.get("/auth/me")
    assert resp.status_code == 401
    body = resp.json()
    assert isinstance(body["detail"], str) and body["detail"]
    assert "Traceback" not in resp.text


# ── Unhandled exception → error_id, never the stack ────────────────────────────

@app.get("/_test/boom", include_in_schema=False)
def _boom():
    raise RuntimeError("boom-internal-secret")


def test_unhandled_exception_returns_error_id_not_stack():
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/_test/boom")
    assert resp.status_code == 500
    body = resp.json()
    assert body["error_id"]
    # The client must get a correlation id, never internals
    assert "boom-internal-secret" not in resp.text
    assert "Traceback" not in resp.text
    assert "RuntimeError" not in resp.text


def test_deep_health_shape_lists_fix_for_every_failing_check():
    client = TestClient(app)
    resp = client.get("/health", params={"deep": 1})
    assert resp.status_code in (200, 503)
    body = resp.json()
    assert body["status"] in ("ok", "degraded", "error")
    assert isinstance(body["checks"], list) and body["checks"]
    for check in body["checks"]:
        assert {"name", "ok", "detail"} <= set(check)
        if not check["ok"]:
            assert check["fix"], f"failing check {check['name']} must carry a fix"


def test_shallow_health_stays_fast_and_simple():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
