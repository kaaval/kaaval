# Kaaval × Kyverno policies

Kaaval's RBAC scanner (`control-plane/app/rbac_service.py`) evaluates the
*live* state of a cluster and ranks findings with the Contextual Risk Score.
Kyverno enforces the same rules at *admission time*, before a risky object
ever exists. The two compose: Kyverno prevents, Kaaval detects what predates
the policy (or slipped past it), explains the risk, and ranks the cleanup.

This directory holds the admission-time counterparts of Kaaval's RBAC rules —
and is honest about which of them the [Kyverno policy
library](https://github.com/kyverno/policies) already provides. Deploying a
duplicate of an upstream policy from here would only invite drift; use the
upstream ones where they exist.

## Coverage map: Kaaval rule → Kyverno policy

Verified against `kyverno/policies` `main`, 2026-07-07.

| Kaaval `rule_type` | CIS v1.12.0 | Kyverno admission policy | Status |
|---|---|---|---|
| `wildcard_permissions` | 5.1.3 | [`restrict-wildcard-verbs`](https://kyverno.io/policies/other/restrict-wildcard-verbs/restrict-wildcard-verbs/), [`restrict-wildcard-resources`](https://kyverno.io/policies/other/restrict-wildcard-resources/restrict-wildcard-resources/) | **upstream — use those** |
| `broad_secrets_access` | 5.1.2 | [`restrict-secret-role-verbs`](https://kyverno.io/policies/other/restrict-secret-role-verbs/restrict-secret-role-verbs/) | **upstream — use that** |
| `cluster_admin_binding` | 5.1.1 (+5.1.7) | [`restrict-binding-clusteradmin`](https://kyverno.io/policies/other/restrict-binding-clusteradmin/restrict-binding-clusteradmin/) blocks *all* cluster-admin bindings; [`restrict-binding-system-groups`](https://kyverno.io/policies/other/restrict-binding-system-groups/restrict-binding-system-groups/) covers 3 of 4 broad groups | partial — see [`restrict-broad-cluster-admin-binding.yaml`](restrict-broad-cluster-admin-binding.yaml) here; the `system:authenticated` gap is **submitted upstream: [kyverno/policies#1508](https://github.com/kyverno/policies/pull/1508)** |
| `exec_attach_grant` | — (RBAC Good Practices, OWASP K03) | none — upstream `block-pod-exec-by-*` policies block exec *requests*, not the RBAC *grant* | **novel** — [`restrict-exec-verbs-roles.yaml`](restrict-exec-verbs-roles.yaml), **submitted upstream: [kyverno/policies#1507](https://github.com/kyverno/policies/pull/1507)** |
| `privilege_escalation_verbs` | 5.1.8 | [`restrict-escalation-verbs-roles`](https://kyverno.io/policies/other/restrict-escalation-verbs-roles/restrict-escalation-verbs-roles/) | **upstream — use that** |
| `node_proxy_access` | 5.1.10 | [`restrict-clusterrole-nodesproxy`](https://kyverno.io/policies/other/restrict-clusterrole-nodesproxy/restrict-clusterrole-nodesproxy/) | **upstream — use that** |
| `csr_approval` | 5.1.11 | [`restrict-clusterrole-csr`](https://github.com/kyverno/policies/tree/main/other/restrict-clusterrole-csr) | **upstream — use that** |
| `webhook_config_access` | 5.1.12 | [`restrict-clusterrole-mutating-validating-admission-webhooks`](https://github.com/kyverno/policies/tree/main/other/restrict-clusterrole-mutating-validating-admission-webhooks) | **upstream — use that** |
| `token_creation` | 5.1.13 | none found | future candidate |
| `workload_creation` | 5.1.4 | too workload-dependent for a blanket admission block — detection + ranking (Kaaval) fits better than prevention | detection-only by design |
| `pv_creation` | 5.1.9 | none found for the RBAC grant | future candidate |

## What's actually in this directory

- **`restrict-exec-verbs-roles.yaml`** — novel: blocks Roles/ClusterRoles
  granting `pods/exec`, `pods/attach`, or `pods/portforward`.
- **`restrict-broad-cluster-admin-binding.yaml`** — a focused variant of
  upstream's `restrict-binding-clusteradmin`: only denies cluster-admin
  bindings to *broad identities* (`default` ServiceAccount,
  `system:authenticated`/`system:unauthenticated`/`system:masters`), for
  clusters where a blanket deny is too strict. Exempts the stock
  `cluster-admin` ClusterRoleBinding.
- **`upstream-candidates/`** — the two artifacts intended for PRs to
  `kyverno/policies`, with test scaffolding in their conventions. Re-verify
  the gaps and run `kyverno test` before submitting.

Both policies ship with `validationFailureAction: Audit`. Kyverno writes the
audit results into PolicyReports — the same objects Kaaval's planned
PolicyReport ingestion will consume, so these policies feed the Contextual
Risk Score pipeline rather than creating a second, parallel alert stream.

Note: policies here were structurally validated (YAML + schema shape).
Run `kyverno test policies/kyverno/upstream-candidates/restrict-exec-verbs-roles`
with the Kyverno CLI before deploying or submitting upstream.
