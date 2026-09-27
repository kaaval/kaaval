"""
POST /rbac/combo-scan scores against the tenant's ScanContext (issue #126).

Same graph, two tenants: a PHI/PCI tenant must get a different Contextual Risk
Score than a tenant on the defaults, and an explicit body `context` must still
override the stored one. The DB-backed context lookup is patched per tenant so
no Postgres is needed.
"""

import os
import uuid
from types import SimpleNamespace

os.environ.setdefault("KAAVAL_ADMIN_PASSWORD", "test-admin-password")

import pytest
from fastapi.testclient import TestClient

from app.auth import get_current_active_user
from app.cve_service import cve_service
from app.database import get_db
from app.main import app
from app.models import ScanContext

DEFAULT_TENANT = uuid.uuid4()
REGULATED_TENANT = uuid.uuid4()

STORED_CONTEXTS = {
    DEFAULT_TENANT: ScanContext(
        tenant_id=DEFAULT_TENANT,
        environment="production",
        data_classification="internal",
        compliance_scope=[],
        exposure="internal",
    ),
    REGULATED_TENANT: ScanContext(
        tenant_id=REGULATED_TENANT,
        environment="production",
        data_classification="phi",
        compliance_scope=["PCI-DSS", "HIPAA"],
        exposure="internet-facing",
    ),
}

# impersonate on users → impersonation_grant (CRITICAL combination finding)
GRAPH = {
    "cluster_roles": [
        {
            "name": "impersonator",
            "kind": "ClusterRole",
            "rules": [{"verbs": ["impersonate"], "resources": ["users"], "api_groups": [""]}],
        }
    ],
    "cluster_role_bindings": [
        {
            "name": "b",
            "kind": "ClusterRoleBinding",
            "roleRef": {"kind": "ClusterRole", "name": "impersonator"},
            "subjects": [{"kind": "ServiceAccount", "name": "attacker", "namespace": "team-a"}],
        }
    ],
}


@pytest.fixture
def lookups(monkeypatch):
    calls = []

    def _stored_context(db, tenant_id):
        calls.append(tenant_id)
        return STORED_CONTEXTS[tenant_id]

    monkeypatch.setattr(cve_service, "get_or_create_scan_context", _stored_context)
    app.dependency_overrides[get_db] = lambda: None
    yield calls
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_current_active_user, None)


def _scan_as(tenant_id, body=None):
    app.dependency_overrides[get_current_active_user] = lambda: SimpleNamespace(tenant_id=tenant_id)
    resp = TestClient(app).post("/rbac/combo-scan", json=body or GRAPH)
    assert resp.status_code == 200, resp.text
    findings = resp.json()["findings"]
    return next(f for f in findings if f["rule_type"] == "impersonation_grant")


def test_combo_scan_uses_the_tenants_stored_context(lookups):
    default = _scan_as(DEFAULT_TENANT)
    regulated = _scan_as(REGULATED_TENANT)

    assert lookups == [DEFAULT_TENANT, REGULATED_TENANT]
    assert regulated["score_factors"] != default["score_factors"]
    assert regulated["contextual_score"] > default["contextual_score"]
    assert regulated["score_factors"]["data_classification"]["value"] == "phi"
    assert regulated["score_factors"]["compliance_scope"]["value"] == ["PCI-DSS", "HIPAA"]


def test_explicit_body_context_overrides_the_stored_one(lookups):
    override = {
        "environment": "dev",
        "data_classification": "public",
        "compliance_scope": [],
        "exposure": "internal",
    }
    finding = _scan_as(REGULATED_TENANT, {**GRAPH, "context": override})

    assert lookups == []  # no DB lookup when the caller supplies a context
    assert finding["score_factors"]["data_classification"]["value"] == "public"
    assert finding["score_factors"]["environment"]["value"] == "dev"
