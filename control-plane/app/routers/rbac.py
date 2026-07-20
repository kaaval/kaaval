"""RBAC scan router — misconfiguration findings scored by the shared Contextual Risk Score engine."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..auth import get_current_active_user
from ..rbac_service import diff_latest_scans, get_latest_rbac_scan, scan_rbac
from ..effective_access import evaluate_combo_findings
from ..report_service import build_rbac_scan_pdf

router = APIRouter(prefix="/rbac", tags=["RBAC"])


# ── Pydantic models for combo-scan ────────────────────────────────────────────

class ComboScanRequest(BaseModel):
    """
    Pass any synthetic RBAC graph to test the combo-escalation predicates
    without needing a live cluster.  All fields are optional — omit a key
    and it defaults to an empty list.

    Shape mirrors K8sClient.get_rbac_graph_data() output exactly.
    """
    roles: list[dict] = []
    cluster_roles: list[dict] = []
    role_bindings: list[dict] = []
    cluster_role_bindings: list[dict] = []
    context: Optional[dict] = None  # override risk context; defaults to production/internal


_DEFAULT_CONTEXT = {
    "environment": "production",
    "data_classification": "internal",
    "exposure": "internal",
}


# ── Existing endpoints ────────────────────────────────────────────────────────

@router.post("/scan")
def run_rbac_scan(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """
    Scan the live cluster's Roles, ClusterRoles, and bindings for
    misconfigurations (wildcard permissions, cluster-admin bound to broad
    identities, broad secrets access, exec/attach grants), scored by the
    same Contextual Risk Score engine CVE findings use.
    """
    return scan_rbac(db, user.tenant_id)


@router.get("/scan/latest")
def get_latest_scan(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Return the most recent RBAC scan result."""
    result = get_latest_rbac_scan(db)
    if not result:
        return {"message": "No scan results yet. POST /rbac/scan to run the first scan."}
    return result


@router.get("/scan/diff")
def get_scan_diff(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Return findings added, resolved, or unchanged since the previous scan."""
    return diff_latest_scans(db)


@router.get("/scan/latest/report.pdf")
def get_latest_scan_report_pdf(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Download the most recent RBAC scan as a PDF report."""
    scan = get_latest_rbac_scan(db)
    if not scan:
        raise HTTPException(404, "No scan results yet. Run a scan first.")
    pdf_bytes = build_rbac_scan_pdf(scan)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=kaaval-rbac-report.pdf"},
    )


# ── Combo-escalation endpoints (issue #85) ────────────────────────────────────

@router.post("/combo-scan")
def run_combo_scan(
    body: ComboScanRequest,
    user=Depends(get_current_active_user),
):
    """
    Evaluate combination-escalation predicates against a supplied RBAC graph.

    Accepts the same graph shape as the live cluster scan but lets you POST
    a synthetic graph — useful for testing without a real cluster.

    Returns findings for:
    - combo_role_escalation   (create roles + escalate)
    - combo_bind_escalation   (create rolebindings + bind)
    - impersonation_grant     (impersonate on users/groups/serviceaccounts)
    - privileged_pod_creation (create pods + privileged SA in same namespace)
    """
    graph = {
        "roles": body.roles,
        "cluster_roles": body.cluster_roles,
        "role_bindings": body.role_bindings,
        "cluster_role_bindings": body.cluster_role_bindings,
    }
    context = body.context or _DEFAULT_CONTEXT
    findings = evaluate_combo_findings(graph, context)
    return {
        "total_subjects_checked": len({
            (s.get("kind"), s.get("name"), s.get("namespace"))
            for binding in body.cluster_role_bindings + body.role_bindings
            for s in binding.get("subjects", [])
        }),
        "combo_findings_count": len(findings),
        "findings": findings,
    }


@router.get("/combo-scan/demo")
def run_combo_scan_demo(
    user=Depends(get_current_active_user),
):
    """
    Run the combo-scan against a built-in demo graph that triggers all four
    predicates.  No request body needed — great for a quick smoke-test.
    """
    demo_graph = {
        "roles": [],
        "cluster_roles": [
            {
                "name": "role-and-escalate",
                "kind": "ClusterRole",
                "rules": [
                    {"verbs": ["create"], "resources": ["roles", "clusterroles"],
                     "api_groups": ["rbac.authorization.k8s.io"]},
                    {"verbs": ["escalate"], "resources": ["clusterroles"],
                     "api_groups": ["rbac.authorization.k8s.io"]},
                ],
            },
            {
                "name": "bind-and-create-bindings",
                "kind": "ClusterRole",
                "rules": [
                    {"verbs": ["create"], "resources": ["rolebindings", "clusterrolebindings"],
                     "api_groups": ["rbac.authorization.k8s.io"]},
                    {"verbs": ["bind"], "resources": ["clusterroles"],
                     "api_groups": ["rbac.authorization.k8s.io"]},
                ],
            },
            {
                "name": "impersonator",
                "kind": "ClusterRole",
                "rules": [
                    {"verbs": ["impersonate"], "resources": ["users", "groups", "serviceaccounts"],
                     "api_groups": [""]},
                ],
            },
            {
                "name": "pod-creator",
                "kind": "ClusterRole",
                "rules": [
                    {"verbs": ["create"], "resources": ["pods"], "api_groups": [""]},
                ],
            },
            {
                "name": "cluster-admin-equivalent",
                "kind": "ClusterRole",
                "rules": [
                    {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"]},
                ],
            },
        ],
        "role_bindings": [],
        "cluster_role_bindings": [
            {
                "name": "attacker-role-escalation",
                "roleRef": {"kind": "ClusterRole", "name": "role-and-escalate"},
                "subjects": [{"kind": "ServiceAccount", "name": "attacker-sa", "namespace": "team-red"}],
            },
            {
                "name": "attacker-bind-escalation",
                "roleRef": {"kind": "ClusterRole", "name": "bind-and-create-bindings"},
                "subjects": [{"kind": "ServiceAccount", "name": "attacker-sa", "namespace": "team-red"}],
            },
            {
                "name": "attacker-impersonate",
                "roleRef": {"kind": "ClusterRole", "name": "impersonator"},
                "subjects": [{"kind": "ServiceAccount", "name": "attacker-sa", "namespace": "team-red"}],
            },
            {
                "name": "attacker-pod-create",
                "roleRef": {"kind": "ClusterRole", "name": "pod-creator"},
                "subjects": [{"kind": "ServiceAccount", "name": "attacker-sa", "namespace": "team-red"}],
            },
            {
                "name": "privileged-sa-binding",
                "roleRef": {"kind": "ClusterRole", "name": "cluster-admin-equivalent"},
                "subjects": [{"kind": "ServiceAccount", "name": "powerful-sa", "namespace": "team-red"}],
            },
        ],
    }

    findings = evaluate_combo_findings(demo_graph, _DEFAULT_CONTEXT)
    return {
        "note": "Demo graph — triggers all four combo-escalation predicates",
        "combo_findings_count": len(findings),
        "rule_types_fired": sorted({f["rule_type"] for f in findings}),
        "findings": findings,
    }
