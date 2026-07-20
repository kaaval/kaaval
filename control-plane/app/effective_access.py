"""
Combination-escalation predicates for the Effective Access Graph (issue #85).

Some privilege-escalation paths only materialise when a subject holds *two*
partial grants at the same time — each half harmless in isolation, together a
full takeover.  These predicates operate on the **aggregated rule set** of an
identity (i.e. all rules flattened across every Role/ClusterRole it is bound
to), not on any single Role.

Each predicate returns a finding dict (same shape as rbac_service findings) or
None, and carries a distinct ``rule_type`` so scoring picks it up with zero
changes.

Exported entry-point
--------------------
``evaluate_combo_findings(graph, context) -> list[dict]``
    Calls all four predicates for every (subject, aggregate-rule-set) pair in
    the RBAC graph and returns the scored findings list.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Optional

from .remediation import build_remediation
from .scoring import compute_contextual_score

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers — verb/resource checks on a single rule dict
# ---------------------------------------------------------------------------

def _has_verb(rule: dict, *verbs: str) -> bool:
    rule_verbs = set(rule.get("verbs") or [])
    return bool(rule_verbs & set(verbs)) or "*" in rule_verbs


def _has_resource(rule: dict, *resources: str) -> bool:
    rule_resources = set(rule.get("resources") or [])
    return bool(rule_resources & set(resources)) or "*" in rule_resources


# ---------------------------------------------------------------------------
# Predicate 1 — combo_role_escalation
#   create roles  +  escalate
#   Together: create a role with any verbs you want, then escalate into it.
# ---------------------------------------------------------------------------

def _can_create_roles(rules: list[dict]) -> bool:
    return any(_has_resource(r, "roles", "clusterroles") and _has_verb(r, "create") for r in rules)


def _can_escalate(rules: list[dict]) -> bool:
    return any(_has_verb(r, "escalate") for r in rules)


def _combo_role_escalation(rules: list[dict]) -> Optional[dict]:
    if _can_create_roles(rules) and _can_escalate(rules):
        return {
            "rule_type": "combo_role_escalation",
            "severity": "CRITICAL",
            "detail": (
                "Subject can both create roles/clusterroles and use the 'escalate' verb: "
                "they can create a role with arbitrary permissions and escalate into it, "
                "achieving full privilege escalation without touching existing roles."
            ),
        }
    return None


# ---------------------------------------------------------------------------
# Predicate 2 — combo_bind_escalation
#   create rolebindings  +  bind
#   Together: create a binding to *any* existing role, including cluster-admin.
# ---------------------------------------------------------------------------

def _can_create_bindings(rules: list[dict]) -> bool:
    return any(
        _has_resource(r, "rolebindings", "clusterrolebindings") and _has_verb(r, "create")
        for r in rules
    )


def _can_bind(rules: list[dict]) -> bool:
    return any(_has_verb(r, "bind") for r in rules)


def _combo_bind_escalation(rules: list[dict]) -> Optional[dict]:
    if _can_create_bindings(rules) and _can_bind(rules):
        return {
            "rule_type": "combo_bind_escalation",
            "severity": "CRITICAL",
            "detail": (
                "Subject can both create rolebindings/clusterrolebindings and use the 'bind' verb: "
                "they can bind any existing role — including cluster-admin — to themselves or "
                "any other identity, achieving privilege escalation via binding."
            ),
        }
    return None


# ---------------------------------------------------------------------------
# Predicate 3 — impersonation_grant
#   impersonate (users / groups / serviceaccounts)
#   A single verb, but only meaningful across the aggregate rule set for the
#   subject.  Fires when the aggregate contains the impersonate verb targeting
#   users, groups, or serviceaccounts.
# ---------------------------------------------------------------------------

_IMPERSONATABLE_RESOURCES = {"users", "groups", "serviceaccounts", "userextras"}


def _can_impersonate(rules: list[dict]) -> bool:
    return any(
        _has_verb(r, "impersonate") and _has_resource(r, *_IMPERSONATABLE_RESOURCES)
        for r in rules
    )


def _impersonation_grant(rules: list[dict]) -> Optional[dict]:
    if _can_impersonate(rules):
        return {
            "rule_type": "impersonation_grant",
            "severity": "CRITICAL",
            "detail": (
                "Subject holds the 'impersonate' verb on users, groups, or serviceaccounts: "
                "they can send requests as any other identity, bypassing all RBAC controls "
                "that target those identities — including cluster-admin."
            ),
        }
    return None


# ---------------------------------------------------------------------------
# Predicate 4 — privileged_pod_creation
#   create pods  +  a ServiceAccount in the same namespace with elevated grants
#   The effective path: spin up a pod that mounts a powerful SA's token, then
#   use that token.  We approximate "powerful SA in namespace" as: any SA in
#   the namespace holds cluster-admin / wildcard / secret-read / exec grants.
#   At graph-evaluation time we flag when the subject can create pods AND the
#   namespace contains at least one non-default SA bound to a risky role.
# ---------------------------------------------------------------------------

def _can_create_pods(rules: list[dict]) -> bool:
    return any(_has_resource(r, "pods") and _has_verb(r, "create") for r in rules)


def _privileged_pod_creation(
    rules: list[dict],
    namespace: Optional[str],
    namespace_has_privileged_sa: bool,
) -> Optional[dict]:
    """
    Fires when:
    - The aggregate rule set allows pod creation, AND
    - The namespace (or cluster scope) has at least one privileged ServiceAccount
      bound to a powerful role — detected by the caller via ``namespace_has_privileged_sa``.
    """
    if _can_create_pods(rules) and namespace_has_privileged_sa:
        scope = f"namespace '{namespace}'" if namespace else "cluster scope"
        return {
            "rule_type": "privileged_pod_creation",
            "severity": "HIGH",
            "detail": (
                f"Subject can create pods in {scope}, which contains a ServiceAccount "
                "bound to a privileged role.  By mounting that ServiceAccount's token "
                "in a new pod, the subject can act as the privileged identity without "
                "ever being directly bound to it."
            ),
        }
    return None


# ---------------------------------------------------------------------------
# Graph helpers — build per-subject aggregate rule sets
# ---------------------------------------------------------------------------

def _flatten_rules_for_subject(
    subject_key: tuple,
    all_bindings: list[dict],
    role_index: dict[tuple, dict],
) -> list[dict]:
    """Return all rules across every Role/ClusterRole bound to ``subject_key``."""
    rules: list[dict] = []
    for binding in all_bindings:
        subjects = binding.get("subjects") or []
        if not any(_subject_key(s) == subject_key for s in subjects):
            continue
        role_ref = binding.get("roleRef") or {}
        role_kind = role_ref.get("kind")
        role_name = role_ref.get("name")
        binding_ns = binding.get("namespace")
        lookup_ns = binding_ns if role_kind == "Role" else None
        role = role_index.get((role_kind, lookup_ns, role_name))
        if role:
            rules.extend(role.get("rules") or [])
    return rules


def _subject_key(subject: dict) -> tuple:
    return (subject.get("kind"), subject.get("name"), subject.get("namespace"))


def _subject_description(subject: dict) -> str:
    kind = subject.get("kind", "Unknown")
    name = subject.get("name", "?")
    ns = subject.get("namespace")
    return f"{kind}/{name}" + (f" (ns: {ns})" if ns else "")


# ---------------------------------------------------------------------------
# Privileged-SA-in-namespace detection helper
# ---------------------------------------------------------------------------

_POWERFUL_VERBS = {"escalate", "bind", "impersonate"}
_BROAD_READ = {"get", "list", "watch"}


def _role_is_privileged(rules: list[dict]) -> bool:
    """Heuristic: a role is 'privileged' if it grants wildcard, secret read, escalation verbs, or exec."""
    for r in rules:
        verbs = set(r.get("verbs") or [])
        resources = set(r.get("resources") or [])
        if "*" in verbs or "*" in resources:
            return True
        if "secrets" in resources and verbs & _BROAD_READ:
            return True
        if verbs & _POWERFUL_VERBS:
            return True
        exec_resources = {"pods/exec", "pods/attach", "pods/portforward"}
        if resources & exec_resources and verbs & {"create", "get"}:
            return True
    return False


def _build_privileged_namespaces(
    all_bindings: list[dict],
    role_index: dict[tuple, dict],
) -> set[Optional[str]]:
    """
    Return the set of namespaces (None = cluster scope) that contain at least
    one non-default ServiceAccount bound to a privileged role.
    """
    privileged_ns: set[Optional[str]] = set()
    for binding in all_bindings:
        subjects = binding.get("subjects") or []
        has_sa = any(
            s.get("kind") == "ServiceAccount" and s.get("name") != "default"
            for s in subjects
        )
        if not has_sa:
            continue
        role_ref = binding.get("roleRef") or {}
        role_kind = role_ref.get("kind")
        role_name = role_ref.get("name")
        binding_ns = binding.get("namespace")
        lookup_ns = binding_ns if role_kind == "Role" else None
        role = role_index.get((role_kind, lookup_ns, role_name))
        if role and _role_is_privileged(role.get("rules") or []):
            # The namespace where the SA can be mounted is the SA's own namespace
            for s in subjects:
                if s.get("kind") == "ServiceAccount" and s.get("name") != "default":
                    sa_ns = s.get("namespace")
                    privileged_ns.add(sa_ns)
    return privileged_ns


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

def evaluate_combo_findings(graph: dict, context: dict) -> list[dict]:
    """
    Evaluate all four combination-escalation predicates against the RBAC graph
    and return a scored findings list in the same shape as rbac_service findings.

    Args:
        graph:   Output of K8sClient.get_rbac_graph_data() (or a synthetic dict
                 with the same keys for testing).
        context: Risk context dict (same keys as rbac_service uses).

    Returns:
        List of finding dicts, sorted descending by contextual_score.
    """
    role_index: dict[tuple, dict] = {}
    for r in graph.get("roles", []):
        role_index[("Role", r.get("namespace"), r["name"])] = r
    for r in graph.get("cluster_roles", []):
        role_index[("ClusterRole", None, r["name"])] = r

    all_bindings = (
        [{**b, "binding_kind": "RoleBinding"} for b in graph.get("role_bindings", [])]
        + [{**b, "binding_kind": "ClusterRoleBinding"} for b in graph.get("cluster_role_bindings", [])]
    )

    privileged_namespaces = _build_privileged_namespaces(all_bindings, role_index)

    # Collect all unique subjects across all bindings
    subject_to_bindings: dict[tuple, list[dict]] = defaultdict(list)
    for binding in all_bindings:
        for subject in binding.get("subjects") or []:
            key = _subject_key(subject)
            subject_to_bindings[key].append(binding)

    findings: list[dict] = []

    for subject_key, bindings in subject_to_bindings.items():
        # Representative subject dict for display
        representative_binding = bindings[0]
        representative_subject = next(
            s for s in (representative_binding.get("subjects") or [])
            if _subject_key(s) == subject_key
        )
        subject_ns = representative_subject.get("namespace")

        aggregate_rules = _flatten_rules_for_subject(subject_key, all_bindings, role_index)
        if not aggregate_rules:
            continue

        # Determine whether any binding namespace for this subject has a privileged SA
        has_privileged_sa = subject_ns in privileged_namespaces or None in privileged_namespaces

        predicates = [
            _combo_role_escalation(aggregate_rules),
            _combo_bind_escalation(aggregate_rules),
            _impersonation_grant(aggregate_rules),
            _privileged_pod_creation(aggregate_rules, subject_ns, has_privileged_sa),
        ]

        for risk in predicates:
            if risk is None:
                continue

            contextual_score, score_factors = compute_contextual_score(
                None, risk["severity"], context
            )
            finding: dict = {
                "rule_type": risk["rule_type"],
                "severity": risk["severity"],
                "title": (
                    f"{risk['rule_type'].replace('_', ' ').title()} "
                    f"— {_subject_description(representative_subject)}"
                ),
                "description": risk["detail"],
                "subject": representative_subject,
                "bindings": [
                    {"kind": b["binding_kind"], "name": b.get("name"), "namespace": b.get("namespace")}
                    for b in bindings
                ],
                "contextual_score": contextual_score,
                "score_factors": score_factors,
            }
            finding["remediation"] = build_remediation(finding)
            findings.append(finding)

    findings.sort(key=lambda f: -f["contextual_score"])
    return findings
