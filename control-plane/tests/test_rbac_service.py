"""
Unit tests for the RBAC rule engine (`evaluate_rbac_findings`) — pure-function
tests against synthetic graph dicts shaped exactly like
`K8sClient.get_rbac_graph_data()`'s output. No DB, no live cluster, no
network access needed, unlike the HTTP-level smoke test.
"""

from app.rbac_service import evaluate_rbac_findings

_CONTEXT = {"environment": "production", "data_classification": "internal", "exposure": "internal"}


def _cluster_role(name, rules):
    return {"name": name, "kind": "ClusterRole", "rules": rules}


def _cluster_role_binding(name, role_name, subjects):
    return {
        "name": name,
        "kind": "ClusterRoleBinding",
        "roleRef": {"kind": "ClusterRole", "name": role_name},
        "subjects": subjects,
    }


def test_wildcard_role_flagged():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("wide-open", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "wide-open-binding", "wide-open",
            [{"kind": "ServiceAccount", "name": "app", "namespace": "team-a"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    rule_types = {f["rule_type"] for f in findings}
    assert "wildcard_permissions" in rule_types


def test_secrets_access_flagged():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("secret-reader", [
            {"verbs": ["get", "list"], "resources": ["secrets"], "api_groups": [""], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "secret-reader-binding", "secret-reader",
            [{"kind": "ServiceAccount", "name": "app", "namespace": "team-a"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert any(f["rule_type"] == "broad_secrets_access" for f in findings)


def test_cluster_admin_bound_to_default_service_account_is_critical():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("cluster-admin", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "default-cluster-admin", "cluster-admin",
            [{"kind": "ServiceAccount", "name": "default", "namespace": "kube-system"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    critical = [f for f in findings if f["rule_type"] == "cluster_admin_binding"]
    assert len(critical) == 1
    assert critical[0]["severity"] == "CRITICAL"


def test_scoped_role_with_narrow_subject_is_not_flagged_critical():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("cluster-admin", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "scoped-admin", "cluster-admin",
            [{"kind": "ServiceAccount", "name": "ci-deployer", "namespace": "ci"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert not any(f["rule_type"] == "cluster_admin_binding" for f in findings)
    assert any(f["rule_type"] == "wildcard_permissions" for f in findings)


def test_findings_are_scored_and_sorted_by_contextual_score():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [
            _cluster_role("cluster-admin", [
                {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
            ]),
            _cluster_role("pod-execer", [
                {"verbs": ["create"], "resources": ["pods/exec"], "api_groups": [""], "resource_names": []},
            ]),
        ],
        "cluster_role_bindings": [
            _cluster_role_binding(
                "default-cluster-admin", "cluster-admin",
                [{"kind": "Group", "name": "system:authenticated", "namespace": None}],
            ),
            _cluster_role_binding(
                "execer-binding", "pod-execer",
                [{"kind": "ServiceAccount", "name": "debug-tool", "namespace": "ops"}],
            ),
        ],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    scores = [f["contextual_score"] for f in findings]
    assert scores == sorted(scores, reverse=True)
    assert findings[0]["rule_type"] == "cluster_admin_binding"
    for f in findings:
        assert "score_factors" in f


def test_builtin_system_role_is_not_flagged():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("system:kube-controller-manager", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "system:kube-controller-manager", "system:kube-controller-manager",
            [{"kind": "User", "name": "system:kube-controller-manager", "namespace": None}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert findings == []


def test_cluster_admin_bound_to_builtin_group_is_not_flagged():
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("cluster-admin", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "cluster-admin", "cluster-admin",
            [{"kind": "Group", "name": "system:masters", "namespace": None}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert findings == []


def test_cluster_admin_bound_to_real_service_account_is_still_flagged():
    """The allowlist must not suppress genuine misconfigurations — only
    Kubernetes-managed built-ins."""
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("cluster-admin", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "risky-binding", "cluster-admin",
            [{"kind": "ServiceAccount", "name": "default", "namespace": "team-a"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert any(f["rule_type"] == "cluster_admin_binding" for f in findings)


def test_cluster_admin_bound_to_all_authenticated_users_is_still_critical():
    """system:authenticated looks like a 'system:'-prefixed builtin but is a
    broad-audience group (anyone with a valid token), not a Kubernetes-managed
    control-plane identity -- the allowlist must never suppress this."""
    graph = {
        "roles": [], "role_bindings": [],
        "cluster_roles": [_cluster_role("cluster-admin", [
            {"verbs": ["*"], "resources": ["*"], "api_groups": ["*"], "resource_names": []},
        ])],
        "cluster_role_bindings": [_cluster_role_binding(
            "dangerous-binding", "cluster-admin",
            [{"kind": "Group", "name": "system:authenticated", "namespace": None}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    critical = [f for f in findings if f["rule_type"] == "cluster_admin_binding"]
    assert len(critical) == 1
    assert critical[0]["severity"] == "CRITICAL"


def test_no_matching_role_for_binding_is_skipped_without_error():
    graph = {
        "roles": [], "role_bindings": [], "cluster_roles": [],
        "cluster_role_bindings": [_cluster_role_binding(
            "dangling-binding", "does-not-exist",
            [{"kind": "ServiceAccount", "name": "app", "namespace": "team-a"}],
        )],
    }

    findings = evaluate_rbac_findings(graph, _CONTEXT)

    assert findings == []
