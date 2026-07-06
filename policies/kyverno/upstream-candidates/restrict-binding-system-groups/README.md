# Upstream PR candidate: add `system:authenticated` to `restrict-binding-system-groups`

**Target:** `kyverno/policies` → `other/restrict-binding-system-groups/restrict-binding-system-groups.yaml`
(and its `other-cel/` and `other-vpol/` variants).

## The gap

The upstream policy (verified against `main`, 2026-07-07) blocks bindings to
`system:anonymous`, `system:unauthenticated`, and `system:masters` — but **not
`system:authenticated`**, the group containing every principal with a valid
token (all users, all ServiceAccounts). Binding a privileged role to
`system:authenticated` is a classic cluster-takeover misconfiguration —
kubectl even prints a dedicated warning when you create such a binding —
and the group is strictly broader in blast radius than `system:masters`
membership abuse, which the policy already blocks.

Argus's RBAC scanner treats `system:authenticated` as a broad-audience
identity and flags privileged bindings to it as CRITICAL
(`control-plane/app/rbac_service.py`, `_BROAD_GROUPS`).

## The proposed rule (mirrors the existing three rules exactly)

```yaml
    - name: restrict-authenticated
      match:
        any:
        - resources:
            kinds:
              - RoleBinding
              - ClusterRoleBinding
      validate:
        message: "Binding to system:authenticated is not allowed."
        pattern:
          subjects:
            - name: "!system:authenticated"
```

Also update `policies.kyverno.io/description` to mention the fourth group,
and extend the `.kyverno-test` resources with a failing
`ClusterRoleBinding` to `system:authenticated`.

## Pre-submission checklist

- [ ] Re-verify against `kyverno/policies` `main` that the gap still exists
- [ ] Run `kyverno test` on the modified policy directory
- [ ] Apply the same rule to the `other-cel` and `other-vpol` variants
- [ ] Submit under your own GitHub identity, referencing this analysis
