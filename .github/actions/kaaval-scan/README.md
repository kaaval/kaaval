# Kaaval RBAC Scan — GitHub Action

Scan Kubernetes RBAC manifests (shift-left) or a live cluster with
[Kaaval](https://github.com/kaaval/kaaval) and gate your pipeline on the
Contextual Risk Score — context-aware gating instead of a flat severity
threshold.

## Usage

Shift-left, scanning manifests already in the repo:

```yaml
- name: Kaaval RBAC scan
  uses: kaaval/kaaval/.github/actions/kaaval-scan@main
  with:
    manifests: k8s/rbac/
    fail-on-severity: HIGH
```

Live-cluster mode, using a read-only CI service account:

```yaml
- name: Kaaval RBAC scan
  uses: kaaval/kaaval/.github/actions/kaaval-scan@main
  with:
    kubeconfig: .kube/ci-readonly-config
    context-file: kaaval.yaml
    fail-on-score: 20
    output: json
```

For reproducible runs, pin both the action's `uses:` ref and its `kaaval-ref`
input to the same reviewed commit SHA. The action checks out the scanner
separately, and `kaaval-ref` otherwise defaults to `main`.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `manifests` | No | — | Path to RBAC YAML manifests (file or directory) — shift-left mode. |
| `kubeconfig` | No | — | Path to a kubeconfig file — live-cluster mode. Use a read-only CI service account, never a cluster-admin credential. |
| `context-file` | No | — | Path to the `kaaval.yaml` risk context (risk context as code). |
| `fail-on-score` | No | — | Fail the job if any finding's contextual score is `>=` this value. |
| `fail-on-severity` | No | — | Fail the job if any finding is at/above this severity (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`). |
| `output` | No | `table` | Output format: `table`, `json`, `sarif`, `junit`, or `policyreport`. |
| `kaaval-ref` | No | `main` | Git ref of Kaaval to run — pin this for reproducible CI runs. |

Provide `manifests` for shift-left scanning, or `kubeconfig` for a live
cluster — not both. Combine `fail-on-score` and/or `fail-on-severity` to gate
the job; with neither set, the action reports findings without failing the
build.

Branding and this usage guide prepare the action for publication. The action
currently lives in a subdirectory; Marketplace publication remains tracked
in [#34](https://github.com/kaaval/kaaval/issues/34).
