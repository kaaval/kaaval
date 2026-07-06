"""
RBAC misconfiguration scanner.

Evaluates the live cluster's Roles, ClusterRoles, and their bindings against
well-established risk patterns (OWASP Kubernetes Top 10 K03, CIS Benchmark
5.1.x) and scores each finding through the shared Contextual Risk Score
engine (scoring.py) — the same one CVE findings use.
"""

import logging
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from .models import RBACScanResult
from .scoring import compute_contextual_score

logger = logging.getLogger(__name__)

_EMPTY_GRAPH = {"roles": [], "cluster_roles": [], "role_bindings": [], "cluster_role_bindings": []}

# Identities broad enough that granting them anything risky matters cluster-wide.
_BROAD_SERVICE_ACCOUNTS = {"default"}
_BROAD_GROUPS = {"system:authenticated", "system:unauthenticated"}

_EXEC_RESOURCES = {"pods/exec", "pods/attach", "pods/portforward"}

# Kubernetes-managed built-ins (core control-plane roles/identities like
# system:kube-controller-manager, system:node, kubeadm:cluster-admins). These
# are expected to hold broad permissions as part of normal cluster operation —
# flagging them produces true-positive-but-useless noise on every real
# cluster, drowning out actual user misconfigurations. Skipped entirely.
_BUILTIN_PREFIXES = ("system:", "kubeadm:")


def _is_builtin_role(role_name: str) -> bool:
    return (role_name or "").startswith(_BUILTIN_PREFIXES)


def _is_builtin_subject(subject: dict) -> bool:
    if subject.get("kind") not in ("Group", "User"):
        return False
    name = subject.get("name") or ""
    # system:authenticated/unauthenticated are broad-audience groups (anyone/no
    # one), not Kubernetes-managed control-plane identities — binding risky
    # roles to them is a genuine, critical misconfiguration, never noise.
    if name in _BROAD_GROUPS:
        return False
    return name.startswith(_BUILTIN_PREFIXES)


def _all_subjects_builtin(subjects: list) -> bool:
    return bool(subjects) and all(_is_builtin_subject(s) for s in subjects)


def _is_wildcard_open(rule: dict) -> bool:
    return "*" in (rule.get("verbs") or []) or "*" in (rule.get("resources") or [])


def _grants_secrets_access(rule: dict) -> bool:
    resources = rule.get("resources") or []
    verbs = rule.get("verbs") or []
    return "secrets" in resources and any(v in verbs for v in ("get", "list", "watch"))


def _grants_exec_attach(rule: dict) -> bool:
    resources = rule.get("resources") or []
    verbs = rule.get("verbs") or []
    return bool(_EXEC_RESOURCES & set(resources)) and any(v in verbs for v in ("create", "get"))


def _is_cluster_admin_equivalent(role_name: str, rules: list) -> bool:
    if role_name == "cluster-admin":
        return True
    return any(
        _is_wildcard_open(r) and "*" in (r.get("api_groups") or [])
        for r in rules
    )


def _evaluate_role_risks(rules: list, is_cluster_scoped: bool) -> list[dict]:
    """Return risk flags for one Role/ClusterRole's rule set."""
    risks = []

    if any(_is_wildcard_open(r) for r in rules):
        risks.append({
            "rule_type": "wildcard_permissions",
            "severity": "HIGH" if is_cluster_scoped else "MEDIUM",
            "detail": "Grants wildcard (*) verbs or resources.",
        })

    if any(_grants_secrets_access(r) for r in rules):
        risks.append({
            "rule_type": "broad_secrets_access",
            "severity": "HIGH" if is_cluster_scoped else "MEDIUM",
            "detail": "Can read/list/watch Secrets — list returns full secret contents, not just names.",
        })

    if any(_grants_exec_attach(r) for r in rules):
        risks.append({
            "rule_type": "exec_attach_grant",
            "severity": "MEDIUM",
            "detail": "Can exec/attach/port-forward into pods — equivalent to code execution access.",
        })

    return risks


def _broad_identity_in(subjects: list) -> Optional[str]:
    """Return a human description if any subject is a broad/default identity, else None."""
    for subject in subjects:
        kind = subject.get("kind")
        name = subject.get("name")
        if kind == "ServiceAccount" and name in _BROAD_SERVICE_ACCOUNTS:
            return f"ServiceAccount '{name}' in namespace '{subject.get('namespace', '?')}'"
        if kind == "Group" and name in _BROAD_GROUPS:
            return f"group '{name}'"
    return None


def evaluate_rbac_findings(graph: dict, context: dict) -> list[dict]:
    """
    Pure function: given the RBAC graph shape from K8sClient.get_rbac_graph_data()
    and a risk context, return scored, explainable findings — one per
    (risky role, binding) pair, naming the actual subject that has the access.
    """
    findings = []

    role_index: dict[tuple, dict] = {}
    for r in graph.get("roles", []):
        role_index[("Role", r["namespace"], r["name"])] = r
    for r in graph.get("cluster_roles", []):
        role_index[("ClusterRole", None, r["name"])] = r

    all_bindings = (
        [{**b, "binding_kind": "RoleBinding"} for b in graph.get("role_bindings", [])]
        + [{**b, "binding_kind": "ClusterRoleBinding"} for b in graph.get("cluster_role_bindings", [])]
    )

    for binding in all_bindings:
        role_ref = binding.get("roleRef", {})
        role_kind = role_ref.get("kind")
        role_name = role_ref.get("name")
        namespace = binding.get("namespace")  # None for ClusterRoleBinding
        role = role_index.get((role_kind, namespace if role_kind == "Role" else None, role_name))
        if not role:
            continue

        subjects = binding.get("subjects", [])
        if _is_builtin_role(role_name) or _all_subjects_builtin(subjects):
            continue

        rules = role.get("rules", [])
        is_cluster_scoped = role_kind == "ClusterRole"

        risks = _evaluate_role_risks(rules, is_cluster_scoped)

        broad_identity = _broad_identity_in(subjects)
        if broad_identity and _is_cluster_admin_equivalent(role_name, rules):
            risks.append({
                "rule_type": "cluster_admin_binding",
                "severity": "CRITICAL",
                "detail": f"Grants cluster-admin-equivalent access to {broad_identity}.",
            })

        for risk in risks:
            # RBAC findings have no CVSS score — severity band alone drives the base value.
            contextual_score, score_factors = compute_contextual_score(None, risk["severity"], context)
            findings.append({
                "rule_type": risk["rule_type"],
                "severity": risk["severity"],
                "title": f"{risk['rule_type'].replace('_', ' ').title()} via {role_kind} '{role_name}'",
                "description": risk["detail"],
                "role": {"kind": role_kind, "name": role_name},
                "binding": {
                    "kind": binding["binding_kind"], "name": binding.get("name"), "namespace": namespace,
                },
                "subjects": subjects,
                "contextual_score": contextual_score,
                "score_factors": score_factors,
            })

    findings.sort(key=lambda f: -f["contextual_score"])
    return findings


def _severity_breakdown(findings: list) -> dict:
    breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        breakdown[sev] = breakdown.get(sev, 0) + 1
    return breakdown


def _format_scan_result(scan: RBACScanResult) -> dict:
    findings = scan.findings or []
    return {
        "scan_id": str(scan.id),
        "scanned_at": scan.scanned_at.isoformat(),
        "total_bindings_checked": scan.total_bindings_checked,
        "affected_count": scan.affected_count,
        "severity_breakdown": _severity_breakdown(findings),
        "findings": findings,
        "status": scan.status,
    }


def scan_rbac(db: Session, tenant_id: UUID) -> dict:
    """Run an RBAC scan against the in-cluster K8sClient and persist the result."""
    from .k8s_client import K8sClient
    from .cve_service import cve_service

    k8s = K8sClient()
    graph = _EMPTY_GRAPH
    if k8s.authorized:
        fetched = k8s.get_rbac_graph_data()
        if "error" not in fetched:
            graph = fetched
        else:
            logger.warning(f"Could not fetch RBAC graph: {fetched['error']}")

    context = cve_service._context_to_dict(cve_service.get_or_create_scan_context(db, tenant_id))
    findings = evaluate_rbac_findings(graph, context)

    total_bindings = len(graph.get("role_bindings", [])) + len(graph.get("cluster_role_bindings", []))

    result = RBACScanResult(
        total_bindings_checked=total_bindings,
        affected_count=len(findings),
        findings=findings,
        status="completed",
    )
    db.add(result)
    db.commit()

    return _format_scan_result(result)


def get_latest_rbac_scan(db: Session) -> Optional[dict]:
    scan = db.query(RBACScanResult).order_by(RBACScanResult.scanned_at.desc()).first()
    if not scan:
        return None
    return _format_scan_result(scan)
