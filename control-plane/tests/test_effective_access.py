"""
Tests for the combination-escalation predicates in effective_access.py (issue #85).

Acceptance criteria (from the issue):
- Each predicate fires **only** on the aggregate rule set (a subject holding
  the halves in two different roles), never on either half alone.
- One positive test + one negative test per predicate (at minimum).
- Findings carry the standard shape so scoring picks them up with zero changes.

Run with:
    cd control-plane
    KAAVAL_ADMIN_PASSWORD=test-admin-password python -m pytest tests/test_effective_access.py -k combo -v
"""

import pytest
from app.effective_access import evaluate_combo_findings

_CONTEXT = {
    "environment": "production",
    "data_classification": "internal",
    "exposure": "internal",
}

# ---------------------------------------------------------------------------
# Graph-building helpers (mirror the style in test_rbac_service.py)
# ---------------------------------------------------------------------------

def _cluster_role(name: str, rules: list) -> dict:
    return {"name": name, "kind": "ClusterRole", "rules": rules}


def _role(name: str, namespace: str, rules: list) -> dict:
    return {"name": name, "kind": "Role", "namespace": namespace, "rules": rules}


def _crb(name: str, role_name: str, subjects: list) -> dict:
    """ClusterRoleBinding."""
    return {
        "name": name,
        "kind": "ClusterRoleBinding",
        "roleRef": {"kind": "ClusterRole", "name": role_name},
        "subjects": subjects,
    }


def _rb(name: str, role_name: str, namespace: str, subjects: list, role_kind: str = "Role") -> dict:
    """RoleBinding."""
    return {
        "name": name,
        "kind": "RoleBinding",
        "namespace": namespace,
        "roleRef": {"kind": role_kind, "name": role_name},
        "subjects": subjects,
    }


def _sa(name: str, namespace: str = "default") -> dict:
    return {"kind": "ServiceAccount", "name": name, "namespace": namespace}


_SUBJECT = [_sa("attacker", "team-a")]


def _graph(roles=None, cluster_roles=None, role_bindings=None, cluster_role_bindings=None):
    return {
        "roles": roles or [],
        "cluster_roles": cluster_roles or [],
        "role_bindings": role_bindings or [],
        "cluster_role_bindings": cluster_role_bindings or [],
    }


# ---------------------------------------------------------------------------
# combo_role_escalation
# ---------------------------------------------------------------------------

class TestComboRoleEscalation:
    """create roles + escalate verb → full privilege escalation."""

    def test_combo_fires_when_both_halves_held_across_two_roles(self):
        """Positive: subject holds create-roles in role-A and escalate in role-B."""
        role_a = _cluster_role("role-creator", [
            {"verbs": ["create"], "resources": ["roles", "clusterroles"], "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        role_b = _cluster_role("escalator", [
            {"verbs": ["escalate"], "resources": ["clusterroles"], "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        graph = _graph(
            cluster_roles=[role_a, role_b],
            cluster_role_bindings=[
                _crb("binding-a", "role-creator", _SUBJECT),
                _crb("binding-b", "escalator", _SUBJECT),
            ],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        rule_types = {f["rule_type"] for f in findings}
        assert "combo_role_escalation" in rule_types

    def test_combo_does_not_fire_on_create_roles_alone(self):
        """Negative: only create-roles, no escalate verb."""
        role = _cluster_role("role-creator-only", [
            {"verbs": ["create"], "resources": ["roles"], "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        graph = _graph(
            cluster_roles=[role],
            cluster_role_bindings=[_crb("binding", "role-creator-only", _SUBJECT)],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert not any(f["rule_type"] == "combo_role_escalation" for f in findings)

    def test_combo_does_not_fire_on_escalate_alone(self):
        """Negative: only escalate verb, no create-roles."""
        role = _cluster_role("escalator-only", [
            {"verbs": ["escalate"], "resources": ["clusterroles"], "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        graph = _graph(
            cluster_roles=[role],
            cluster_role_bindings=[_crb("binding", "escalator-only", _SUBJECT)],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert not any(f["rule_type"] == "combo_role_escalation" for f in findings)

    def test_combo_finding_has_standard_shape(self):
        """The finding dict carries all fields the scoring engine expects."""
        role_a = _cluster_role("role-creator", [
            {"verbs": ["create"], "resources": ["roles"], "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        role_b = _cluster_role("escalator", [
            {"verbs": ["escalate"], "resources": ["clusterroles"], "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        graph = _graph(
            cluster_roles=[role_a, role_b],
            cluster_role_bindings=[
                _crb("b-a", "role-creator", _SUBJECT),
                _crb("b-b", "escalator", _SUBJECT),
            ],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)
        combo = next(f for f in findings if f["rule_type"] == "combo_role_escalation")

        assert "severity" in combo
        assert "contextual_score" in combo
        assert "score_factors" in combo
        assert "description" in combo
        assert combo["severity"] == "CRITICAL"
        assert combo["contextual_score"] > 0


# ---------------------------------------------------------------------------
# combo_bind_escalation
# ---------------------------------------------------------------------------

class TestComboBindEscalation:
    """create rolebindings + bind verb → bind any existing role to self."""

    def test_combo_fires_when_both_halves_held_across_two_roles(self):
        """Positive: subject holds create-rolebindings in role-A and bind in role-B."""
        role_a = _cluster_role("binding-creator", [
            {"verbs": ["create"], "resources": ["rolebindings", "clusterrolebindings"],
             "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        role_b = _cluster_role("binder", [
            {"verbs": ["bind"], "resources": ["clusterroles"], "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        graph = _graph(
            cluster_roles=[role_a, role_b],
            cluster_role_bindings=[
                _crb("b-a", "binding-creator", _SUBJECT),
                _crb("b-b", "binder", _SUBJECT),
            ],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert any(f["rule_type"] == "combo_bind_escalation" for f in findings)

    def test_combo_does_not_fire_on_create_bindings_alone(self):
        """Negative: only create-rolebindings, no bind verb."""
        role = _cluster_role("binding-creator-only", [
            {"verbs": ["create"], "resources": ["rolebindings"], "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        graph = _graph(
            cluster_roles=[role],
            cluster_role_bindings=[_crb("b", "binding-creator-only", _SUBJECT)],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert not any(f["rule_type"] == "combo_bind_escalation" for f in findings)

    def test_combo_does_not_fire_on_bind_alone(self):
        """Negative: only bind verb, no create-rolebindings."""
        role = _cluster_role("binder-only", [
            {"verbs": ["bind"], "resources": ["clusterroles"], "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        graph = _graph(
            cluster_roles=[role],
            cluster_role_bindings=[_crb("b", "binder-only", _SUBJECT)],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert not any(f["rule_type"] == "combo_bind_escalation" for f in findings)

    def test_combo_fires_for_clusterrolebindings_resource_too(self):
        """Positive: the bind + clusterrolebinding create combo is equally dangerous."""
        role_a = _cluster_role("crb-creator", [
            {"verbs": ["create"], "resources": ["clusterrolebindings"],
             "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        role_b = _cluster_role("binder2", [
            {"verbs": ["bind"], "resources": ["clusterroles"], "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        graph = _graph(
            cluster_roles=[role_a, role_b],
            cluster_role_bindings=[
                _crb("b-a", "crb-creator", _SUBJECT),
                _crb("b-b", "binder2", _SUBJECT),
            ],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert any(f["rule_type"] == "combo_bind_escalation" for f in findings)


# ---------------------------------------------------------------------------
# impersonation_grant
# ---------------------------------------------------------------------------

class TestImpersonationGrant:
    """impersonate on users/groups/serviceaccounts → act as any identity."""

    def test_combo_fires_on_impersonate_users(self):
        """Positive: impersonate + users resource."""
        role = _cluster_role("impersonator", [
            {"verbs": ["impersonate"], "resources": ["users"], "api_groups": [""]},
        ])
        graph = _graph(
            cluster_roles=[role],
            cluster_role_bindings=[_crb("b", "impersonator", _SUBJECT)],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert any(f["rule_type"] == "impersonation_grant" for f in findings)

    def test_combo_fires_on_impersonate_serviceaccounts(self):
        """Positive: impersonate + serviceaccounts resource."""
        role = _cluster_role("sa-impersonator", [
            {"verbs": ["impersonate"], "resources": ["serviceaccounts"], "api_groups": [""]},
        ])
        graph = _graph(
            cluster_roles=[role],
            cluster_role_bindings=[_crb("b", "sa-impersonator", _SUBJECT)],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert any(f["rule_type"] == "impersonation_grant" for f in findings)

    def test_combo_fires_on_impersonate_groups(self):
        """Positive: impersonate + groups resource."""
        role = _cluster_role("group-impersonator", [
            {"verbs": ["impersonate"], "resources": ["groups"], "api_groups": [""]},
        ])
        graph = _graph(
            cluster_roles=[role],
            cluster_role_bindings=[_crb("b", "group-impersonator", _SUBJECT)],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert any(f["rule_type"] == "impersonation_grant" for f in findings)

    def test_combo_does_not_fire_on_impersonate_without_target_resource(self):
        """
        Negative: 'impersonate' verb but no impersonatable resource (e.g., only
        on 'pods' — nonsensical but ensures the resource check is enforced).
        """
        role = _cluster_role("bad-impersonate", [
            {"verbs": ["impersonate"], "resources": ["pods"], "api_groups": [""]},
        ])
        graph = _graph(
            cluster_roles=[role],
            cluster_role_bindings=[_crb("b", "bad-impersonate", _SUBJECT)],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert not any(f["rule_type"] == "impersonation_grant" for f in findings)

    def test_combo_does_not_fire_on_get_users_without_impersonate(self):
        """Negative: get on users is not impersonation."""
        role = _cluster_role("user-reader", [
            {"verbs": ["get", "list"], "resources": ["users"], "api_groups": [""]},
        ])
        graph = _graph(
            cluster_roles=[role],
            cluster_role_bindings=[_crb("b", "user-reader", _SUBJECT)],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert not any(f["rule_type"] == "impersonation_grant" for f in findings)


# ---------------------------------------------------------------------------
# privileged_pod_creation
# ---------------------------------------------------------------------------

class TestPrivilegedPodCreation:
    """create pods in a namespace that contains a privileged ServiceAccount."""

    def _privileged_sa_role(self) -> dict:
        """A ClusterRole that makes its holder 'privileged' in our heuristic."""
        return _cluster_role("privileged-sa-role", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"]},
        ])

    def test_combo_fires_when_pod_creator_and_privileged_sa_share_namespace(self):
        """
        Positive: subject can create pods in namespace 'team-a'; that namespace
        also has a non-default SA bound to a privileged role.
        """
        pod_role = _cluster_role("pod-creator", [
            {"verbs": ["create"], "resources": ["pods"], "api_groups": [""]},
        ])
        priv_role = self._privileged_sa_role()

        attacker = [_sa("attacker", "team-a")]
        privileged_sa = [_sa("powerful-sa", "team-a")]

        graph = _graph(
            cluster_roles=[pod_role, priv_role],
            cluster_role_bindings=[
                _crb("attacker-binding", "pod-creator", attacker),
                _crb("privileged-sa-binding", "privileged-sa-role", privileged_sa),
            ],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert any(f["rule_type"] == "privileged_pod_creation" for f in findings)

    def test_combo_does_not_fire_when_no_privileged_sa_in_namespace(self):
        """
        Negative: subject can create pods, but the namespace only has the default
        SA (no elevated grants).
        """
        pod_role = _cluster_role("pod-creator-no-priv", [
            {"verbs": ["create"], "resources": ["pods"], "api_groups": [""]},
        ])
        harmless_role = _cluster_role("reader", [
            {"verbs": ["get"], "resources": ["configmaps"], "api_groups": [""]},
        ])

        attacker = [_sa("attacker", "team-b")]
        harmless_sa = [_sa("reader-sa", "team-b")]

        graph = _graph(
            cluster_roles=[pod_role, harmless_role],
            cluster_role_bindings=[
                _crb("attacker-binding", "pod-creator-no-priv", attacker),
                _crb("reader-binding", "reader", harmless_sa),
            ],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert not any(f["rule_type"] == "privileged_pod_creation" for f in findings)

    def test_combo_does_not_fire_on_pod_creation_when_only_default_sa_exists(self):
        """
        Negative: the namespace has a 'default' SA (excluded by design) but no
        other elevated SA — the default SA is considered non-privileged noise.
        """
        pod_role = _cluster_role("pod-creator-only", [
            {"verbs": ["create"], "resources": ["pods"], "api_groups": [""]},
        ])
        big_role = _cluster_role("default-sa-role", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"]},
        ])

        attacker = [_sa("attacker", "team-c")]
        default_sa_subjects = [_sa("default", "team-c")]  # excluded by design

        graph = _graph(
            cluster_roles=[pod_role, big_role],
            cluster_role_bindings=[
                _crb("attacker-binding", "pod-creator-only", attacker),
                _crb("default-binding", "default-sa-role", default_sa_subjects),
            ],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert not any(f["rule_type"] == "privileged_pod_creation" for f in findings)


# ---------------------------------------------------------------------------
# Cross-cutting: scoring shape
# ---------------------------------------------------------------------------

class TestFindingShape:
    """All combo findings must carry the shape scoring.py and downstream consumers expect."""

    def _graph_with_combo_role_escalation(self):
        role_a = _cluster_role("rc", [
            {"verbs": ["create"], "resources": ["roles"], "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        role_b = _cluster_role("esc", [
            {"verbs": ["escalate"], "resources": ["clusterroles"], "api_groups": ["rbac.authorization.k8s.io"]},
        ])
        return _graph(
            cluster_roles=[role_a, role_b],
            cluster_role_bindings=[
                _crb("b-rc", "rc", _SUBJECT),
                _crb("b-esc", "esc", _SUBJECT),
            ],
        )

    def test_finding_has_required_scoring_keys(self):
        findings = evaluate_combo_findings(self._graph_with_combo_role_escalation(), _CONTEXT)
        assert findings, "Expected at least one finding"
        for finding in findings:
            assert "rule_type" in finding
            assert "severity" in finding
            assert "contextual_score" in finding
            assert "score_factors" in finding
            assert isinstance(finding["contextual_score"], (int, float))
            assert finding["contextual_score"] > 0

    def test_findings_sorted_descending_by_score(self):
        # Trigger multiple predicates simultaneously
        role = _cluster_role("all-powerful", [
            {"verbs": ["create", "escalate", "bind", "impersonate"],
             "resources": ["roles", "clusterroles", "rolebindings", "clusterrolebindings", "users", "pods"],
             "api_groups": ["*"]},
        ])
        priv_role = _cluster_role("priv", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"]},
        ])
        graph = _graph(
            cluster_roles=[role, priv_role],
            cluster_role_bindings=[
                _crb("all-b", "all-powerful", _SUBJECT),
                _crb("priv-b", "priv", [_sa("elevated-sa", "default")]),
            ],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        scores = [f["contextual_score"] for f in findings]
        assert scores == sorted(scores, reverse=True), "Findings must be sorted descending by score"

    def test_empty_graph_returns_no_findings(self):
        findings = evaluate_combo_findings(_graph(), _CONTEXT)
        assert findings == []


# ---------------------------------------------------------------------------
# Regression: privileged SA in namespace A must not flag pod-creator in namespace B
# Maintainer review comment on PR #105 — required before merge
# ---------------------------------------------------------------------------

class TestPrivilegedPodCreationNamespaceIsolation:
    """
    privileged_pod_creation must never fire across unrelated namespaces.

    Root cause that was fixed: _build_privileged_namespaces() recorded
    s.get("namespace") for each SA subject.  When a SA had no ``namespace``
    key, None was inserted into the set.  The guard
    ``or None in privileged_namespaces`` then matched every pod-creating
    subject regardless of namespace — a false-positive flood.
    """

    def test_privileged_sa_in_ns_a_does_not_flag_pod_creator_in_ns_b(self):
        """
        Reproducer from maintainer review comment:
        - powerful-sa (no namespace key) bound to cluster-admin-equivalent
        - innocent SA in totally-unrelated-ns can create pods
        Expected: NO privileged_pod_creation finding for innocent.
        """
        priv_role = _cluster_role("admin", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"]},
        ])
        pod_role = _cluster_role("podmaker", [
            {"verbs": ["create"], "resources": ["pods"], "api_groups": [""]},
        ])
        graph = _graph(
            cluster_roles=[priv_role, pod_role],
            cluster_role_bindings=[
                # powerful-sa has NO namespace key — the bug inserted None here
                {
                    "name": "priv",
                    "roleRef": {"kind": "ClusterRole", "name": "admin"},
                    "subjects": [{"kind": "ServiceAccount", "name": "powerful"}],
                },
                {
                    "name": "pods",
                    "roleRef": {"kind": "ClusterRole", "name": "podmaker"},
                    "subjects": [{"kind": "ServiceAccount", "name": "innocent",
                                  "namespace": "totally-unrelated-ns"}],
                },
            ],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert not any(f["rule_type"] == "privileged_pod_creation" for f in findings), (
            "privileged_pod_creation must not fire when the privileged SA has no "
            "namespace and the pod-creator is in a completely unrelated namespace"
        )

    def test_privileged_sa_in_same_ns_still_fires(self):
        """
        Positive control: fix must not suppress legitimate same-namespace findings.
        """
        priv_role = _cluster_role("admin2", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"]},
        ])
        pod_role = _cluster_role("podmaker2", [
            {"verbs": ["create"], "resources": ["pods"], "api_groups": [""]},
        ])
        graph = _graph(
            cluster_roles=[priv_role, pod_role],
            cluster_role_bindings=[
                {
                    "name": "priv2",
                    "roleRef": {"kind": "ClusterRole", "name": "admin2"},
                    "subjects": [{"kind": "ServiceAccount", "name": "powerful-sa",
                                  "namespace": "shared-ns"}],
                },
                {
                    "name": "pods2",
                    "roleRef": {"kind": "ClusterRole", "name": "podmaker2"},
                    "subjects": [{"kind": "ServiceAccount", "name": "attacker",
                                  "namespace": "shared-ns"}],
                },
            ],
        )

        findings = evaluate_combo_findings(graph, _CONTEXT)

        assert any(f["rule_type"] == "privileged_pod_creation" for f in findings), (
            "privileged_pod_creation must still fire when privileged SA and "
            "pod-creator share the same namespace"
        )


# ---------------------------------------------------------------------------
# Remediation coverage — issue #88
# Every combo rule_type must have a non-generic remediation action and at
# least one benchmark_ref.  Mirrors test_findings_carry_remediation in
# test_rbac_service.py.
# ---------------------------------------------------------------------------

class TestComboRemediationCoverage:
    """
    Acceptance criteria from issue #88:
    - One remediation entry per new rule_type.
    - Test asserts no new rule_type is missing a remediation.
    """

    def _all_combo_findings(self):
        """Graph that fires all four combo predicates."""
        priv_role = _cluster_role("priv", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"]},
        ])
        combo_role = _cluster_role("all-combos", [
            {"verbs": ["create", "escalate", "bind", "impersonate"],
             "resources": ["roles", "clusterroles", "rolebindings",
                           "clusterrolebindings", "users", "pods"],
             "api_groups": ["*"]},
        ])
        graph = _graph(
            cluster_roles=[combo_role, priv_role],
            cluster_role_bindings=[
                _crb("attacker-b", "all-combos", _SUBJECT),
                _crb("priv-b", "priv", [_sa("elevated-sa", "team-a")]),
            ],
        )
        return evaluate_combo_findings(graph, _CONTEXT)

    def test_every_combo_rule_type_has_remediation(self):
        """No combo finding should fall through to the generic 'Role ?' template."""
        findings = self._all_combo_findings()
        rule_types_seen = set()
        for f in findings:
            rt = f["rule_type"]
            rule_types_seen.add(rt)
            rem = f.get("remediation", {})
            action = rem.get("action", "")
            assert action, f"{rt}: remediation action is empty"
            assert "?" not in action, (
                f"{rt}: action fell through to generic template — "
                f"add a _RBAC_ACTIONS entry in remediation.py. Got: {action!r}"
            )

        expected = {
            "combo_role_escalation",
            "combo_bind_escalation",
            "impersonation_grant",
            "privileged_pod_creation",
        }
        assert expected <= rule_types_seen, (
            f"Missing rule_types in findings: {expected - rule_types_seen}"
        )

    def test_combo_remediation_has_benchmark_refs(self):
        """Each combo finding must carry at least one verified benchmark citation."""
        findings = self._all_combo_findings()
        for f in findings:
            rt = f["rule_type"]
            refs = f.get("remediation", {}).get("benchmark_refs", [])
            assert refs, f"{rt}: no benchmark_refs — add entry to _CIS_REFS in remediation.py"
            for ref in refs:
                assert ref.get("benchmark"), f"{rt}: benchmark_ref missing 'benchmark' key"
                assert ref.get("title"), f"{rt}: benchmark_ref missing 'title' key"

    def test_combo_remediation_has_audit_note(self):
        """audit_note must be present so the access-review log can be populated."""
        findings = self._all_combo_findings()
        for f in findings:
            rt = f["rule_type"]
            audit_note = f.get("remediation", {}).get("audit_note", "")
            assert audit_note, f"{rt}: audit_note is empty"
