"""
Combination-escalation fixtures (issue #128).

The demo graph that used to live behind GET /rbac/combo-scan/demo is now
hack/dev/combo-scan-graph.json. combo_role_escalation already has its dedicated
fixture in hack/dev/rbac-fixtures.yaml (combo-takeover, #86), so the JSON drops
the demo's separate role-and-escalate role. It still fires all four rule_types
on its own (the wildcard-bound powerful-sa also holds create+escalate), which is
what makes it usable as a one-shot `POST /rbac/combo-scan` smoke check.
"""

import json
import os
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("KAAVAL_ADMIN_PASSWORD", "test-admin-password")

from fastapi.testclient import TestClient

from app.cli import build_graph_from_manifests
from app.effective_access import evaluate_combo_findings
from app.main import app

_HACK_DEV = Path(__file__).resolve().parents[2] / "hack" / "dev"
_CONTEXT = {"environment": "production", "data_classification": "internal", "exposure": "internal"}

ALL_COMBO_RULE_TYPES = {
    "combo_role_escalation",
    "combo_bind_escalation",
    "impersonation_grant",
    "privileged_pod_creation",
}


def _combo_graph() -> dict:
    return json.loads((_HACK_DEV / "combo-scan-graph.json").read_text())


def _merged(*graphs: dict) -> dict:
    keys = ("roles", "cluster_roles", "role_bindings", "cluster_role_bindings")
    return {k: [item for g in graphs for item in g.get(k, [])] for k in keys}


def test_fixtures_fire_all_four_combo_rule_types():
    graph = _merged(build_graph_from_manifests(str(_HACK_DEV / "rbac-fixtures.yaml")), _combo_graph())
    fired = {f["rule_type"] for f in evaluate_combo_findings(graph, _CONTEXT)}
    assert ALL_COMBO_RULE_TYPES <= fired, ALL_COMBO_RULE_TYPES - fired


def test_combo_scan_graph_alone_fires_all_four_combo_rule_types():
    fired = {f["rule_type"] for f in evaluate_combo_findings(_combo_graph(), _CONTEXT)}
    assert fired == ALL_COMBO_RULE_TYPES, fired


def test_demo_route_is_gone_from_the_api():
    assert "/rbac/combo-scan/demo" not in app.openapi()["paths"]
    assert TestClient(app).get("/rbac/combo-scan/demo").status_code in (401, 404, 405)


def test_documented_curl_smoke_check_fires_all_four_through_the_api():
    # docs/api.md: POST hack/dev/combo-scan-graph.json to /rbac/combo-scan
    from app.auth import get_current_active_user
    from app.database import get_db

    app.dependency_overrides[get_current_active_user] = lambda: SimpleNamespace(tenant_id=None)
    app.dependency_overrides[get_db] = lambda: None
    try:
        resp = TestClient(app).post(
            "/rbac/combo-scan", json={**_combo_graph(), "context": _CONTEXT}
        )
    finally:
        app.dependency_overrides.pop(get_current_active_user, None)
        app.dependency_overrides.pop(get_db, None)
    assert resp.status_code == 200, resp.text
    assert {f["rule_type"] for f in resp.json()["findings"]} == ALL_COMBO_RULE_TYPES
