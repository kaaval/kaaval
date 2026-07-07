# Kyverno upstream submission guide

Two contributions to [`kyverno/policies`](https://github.com/kyverno/policies),
both closing gaps confirmed against `main` (2026-07-07). Submit under your own
GitHub identity. Everything here is copy-paste ready; the only required step
before opening each PR is re-running `kyverno test` locally and re-confirming
the gap still exists.

## Prerequisite: install the Kyverno CLI and run the tests

```bash
# https://kyverno.io/docs/kyverno-cli/install/
kyverno version
# from this directory:
kyverno test restrict-exec-verbs-roles/
```

Do not open a PR until `kyverno test` passes locally — the repo's CI runs it.

---

## PR 1 — New policy: `restrict-exec-verbs-roles`

**Gap:** the library has `block-pod-exec-by-*` policies, but they block exec
*requests* at admission (the `PodExecOptions` subresource). Nothing restricts
the RBAC *grant* of `pods/exec` / `pods/attach` / `pods/portforward` in a
Role/ClusterRole — the standing permission itself. Analogous grant-restricting
policies already exist for other resources (`restrict-clusterrole-nodesproxy`,
`restrict-escalation-verbs-roles`, `restrict-clusterrole-csr`), so this fits
the library's conventions.

**Files** (place under `other/restrict-exec-verbs-roles/`):
- `restrict-exec-verbs-roles.yaml`
- `artifacthub-pkg.yml`
- `.kyverno-test/kyverno-test.yaml`, `.kyverno-test/resource.yaml`

(Maintainers may also ask for `other-cel/` and `other-vpol/` variants — offer
to add them; the CEL form is a straightforward translation.)

### Suggested PR title
`feat: add restrict-exec-verbs-roles policy`

### Suggested PR body
```
This policy blocks any Role or ClusterRole that grants create/get on
pods/exec, pods/attach, or pods/portforward.

Motivation: the existing block-pod-exec-by-* policies restrict exec
*requests* at admission (PodExecOptions). They don't restrict the RBAC
*grant* — a standing Role/ClusterRole permission that hands out interactive,
code-execution-equivalent access to workloads. That grant is the durable
control worth preventing, and the library already restricts analogous
grants for other resources (restrict-clusterrole-nodesproxy,
restrict-escalation-verbs-roles, restrict-clusterrole-csr).

- Category: Security
- Subject: Role, ClusterRole, RBAC
- `kyverno test` passes (see .kyverno-test/).

Refs: Kubernetes RBAC Good Practices; OWASP Kubernetes Top 10 K03.
```

---

## PR 2 — Add a rule to `restrict-binding-system-groups`

**Gap:** the existing policy blocks bindings to `system:anonymous`,
`system:unauthenticated`, and `system:masters` — but **not**
`system:authenticated`, the group that contains every principal with a valid
token (all users and ServiceAccounts). Binding a privileged role to
`system:authenticated` is a classic cluster-takeover misconfiguration
(kubectl even prints a warning when you create one), and it is broader in
blast radius than the groups the policy already covers.

**Change:** add one `restrict-authenticated` rule (mirroring the three
existing rules) and mention the fourth group in the description. The full
patched file is in `restrict-binding-system-groups/restrict-binding-system-groups.yaml`
here — diff it against upstream to produce the change. Also add a failing
`ClusterRoleBinding` to `system:authenticated` in the policy's
`.kyverno-test` resources, and apply the same rule to the `other-cel/` and
`other-vpol/` variants.

### Suggested PR title
`feat: block system:authenticated in restrict-binding-system-groups`

### Suggested PR body
```
restrict-binding-system-groups blocks bindings to system:anonymous,
system:unauthenticated, and system:masters, but not system:authenticated —
the group of every principal with a valid token (all users + all
ServiceAccounts). Binding a privileged role to it is a common
cluster-takeover misconfiguration and is broader than the groups already
covered.

This adds a restrict-authenticated rule following the existing three, updates
the description, and extends the kyverno-test resources with a failing
binding. Also applied to the other-cel and other-vpol variants.
```

---

## After submitting

Link the PRs back from `policies/kyverno/README.md` (replace "being
contributed upstream" with the PR URLs), and mention them in the SIG Security
Tooling introduction (`docs/sig-security-intro.md`) — "here are two policy
PRs we're bringing" is a stronger opener than a plan.
