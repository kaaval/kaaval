"""RBAC scan router — misconfiguration findings scored by the shared Contextual Risk Score engine."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..auth import get_current_active_user
from ..cve_service import cve_service
from ..rbac_service import diff_latest_scans, get_latest_rbac_scan, scan_rbac
from ..effective_access import evaluate_combo_findings
from ..report_service import build_rbac_scan_pdf
from ..request_limits import json_body_openapi, limited_json_body

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
    context: Optional[dict] = None  # override risk context; defaults to the tenant's stored ScanContext


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

@router.post("/combo-scan", openapi_extra=json_body_openapi(ComboScanRequest))
def run_combo_scan(
    user=Depends(get_current_active_user),  # authenticate before reading the body
    body: ComboScanRequest = Depends(limited_json_body(ComboScanRequest)),
    db: Session = Depends(get_db),
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

    Findings are scored against the tenant's stored ScanContext (the same one
    POST /rbac/scan uses); an explicit ``context`` in the body overrides it.

    Bodies larger than KAAVAL_MAX_REQUEST_BODY_MB (default 20) are rejected
    with a 413 before the graph is parsed or evaluated.
    """
    graph = {
        "roles": body.roles,
        "cluster_roles": body.cluster_roles,
        "role_bindings": body.role_bindings,
        "cluster_role_bindings": body.cluster_role_bindings,
    }
    context = body.context or cve_service._context_to_dict(
        cve_service.get_or_create_scan_context(db, user.tenant_id)
    )
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
