"""
Deep-health / dependency preflight surface.

Each check returns a dict:
    name      short identifier ("postgres", "cve-feeds", "kubernetes")
    ok        bool
    required  whether a failure should fail the whole surface (503)
    detail    what was observed
    fix       (failures only) the exact command or setting that resolves it

`GET /health?deep=1` aggregates these; `GET /health` stays a cheap liveness
probe with no dependency traffic.
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy import text

logger = logging.getLogger(__name__)

# The scheduler refreshes feeds every 24h — two missed cycles means something
# is actually wrong, not just a slow crawl.
FEED_STALE_AFTER_HOURS = 48

_DB_FIX = (
    "Start the bundled database: `cd deploy && docker compose up -d postgres` "
    "— or point DATABASE_URL at your PostgreSQL (see .env.example)."
)


def _safe_url(engine) -> str:
    # SQLAlchemy masks the password when rendering a URL object
    return engine.url.render_as_string(hide_password=True)


def check_database(engine) -> dict:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {
            "name": "postgres",
            "ok": True,
            "required": True,
            "detail": f"reachable at {_safe_url(engine)}",
        }
    except Exception as exc:
        return {
            "name": "postgres",
            "ok": False,
            "required": True,
            "detail": f"cannot connect to {_safe_url(engine)} ({exc.__class__.__name__})",
            "fix": _DB_FIX,
        }


def check_cve_feeds(db) -> dict:
    from .models import CVEFeed

    feeds = db.query(CVEFeed).filter(CVEFeed.enabled == True).all()  # noqa: E712
    if not feeds:
        return {
            "name": "cve-feeds",
            "ok": False,
            "required": False,
            "detail": "no enabled CVE feeds registered",
            "fix": (
                "Restart the control plane (default feeds are seeded on startup) "
                "or register one with POST /cve/feeds."
            ),
        }

    fetched = [f.last_fetched for f in feeds if f.last_fetched]
    if not fetched:
        return {
            "name": "cve-feeds",
            "ok": False,
            "required": False,
            "detail": f"{len(feeds)} feed(s) registered but never refreshed",
            "fix": (
                "Trigger a refresh: POST /cve/feeds/refresh-all (admin token) "
                "— or wait for the 24h scheduler."
            ),
        }

    newest = max(fetched)
    age = datetime.utcnow() - newest
    if age > timedelta(hours=FEED_STALE_AFTER_HOURS):
        return {
            "name": "cve-feeds",
            "ok": False,
            "required": False,
            "detail": (
                f"CVE data is stale — newest refresh {newest.isoformat()}Z "
                f"({int(age.total_seconds() // 3600)}h ago)"
            ),
            "fix": (
                "Trigger a refresh: POST /cve/feeds/refresh-all (admin token) "
                "and check the scheduler logs for repeated fetch failures."
            ),
        }

    return {
        "name": "cve-feeds",
        "ok": True,
        "required": False,
        "detail": f"{len(feeds)} feed(s) enabled, newest refresh {newest.isoformat()}Z",
    }


def check_kubernetes() -> dict:
    from kubernetes import config as k8s_config

    try:
        k8s_config.load_incluster_config()
        return {
            "name": "kubernetes",
            "ok": True,
            "required": False,
            "detail": "in-cluster ServiceAccount credentials",
        }
    except k8s_config.ConfigException:
        pass
    try:
        k8s_config.load_kube_config()
        return {
            "name": "kubernetes",
            "ok": True,
            "required": False,
            "detail": "local kubeconfig",
        }
    except k8s_config.ConfigException:
        return {
            "name": "kubernetes",
            "ok": False,
            "required": False,
            "detail": "no in-cluster ServiceAccount and no readable kubeconfig",
            "fix": (
                "Set KUBECONFIG to a valid kubeconfig, or deploy in-cluster with a "
                "ServiceAccount (deploy/cronjob.yaml shows the minimal RBAC). "
                "Manifest scanning (`scan rbac --manifests`) works without cluster access."
            ),
        }


def run_deep_checks(engine, session_factory) -> dict:
    """Run every preflight; report each failure with its fix command."""
    checks = [check_database(engine)]
    db_ok = checks[0]["ok"]

    if db_ok:
        db = session_factory()
        try:
            checks.append(check_cve_feeds(db))
        except Exception as exc:
            logger.warning(f"cve-feeds preflight errored: {exc}")
            checks.append({
                "name": "cve-feeds",
                "ok": False,
                "required": False,
                "detail": f"preflight query failed ({exc.__class__.__name__})",
                "fix": _DB_FIX,
            })
        finally:
            db.close()
    else:
        checks.append({
            "name": "cve-feeds",
            "ok": False,
            "required": False,
            "detail": "skipped — database unreachable",
            "fix": _DB_FIX,
        })

    checks.append(check_kubernetes())

    if any(not c["ok"] and c["required"] for c in checks):
        status = "error"
    elif any(not c["ok"] for c in checks):
        status = "degraded"
    else:
        status = "ok"

    return {"status": status, "checks": checks}
