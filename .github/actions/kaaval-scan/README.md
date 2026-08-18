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
    fail-on-score: 70
    output: json
```

Pin `@main` to a released tag (for example `@v0.5.0`) once you want a fixed
version instead of always running the latest `main`.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `manifests` | No | — | Path to RBAC YAML manifests (file or directory) — shift-left mode. |
| `kubeconfig` | No | — | Path to a kubeconfig file — live-cluster mode. Use a read-only CI service account, never a cluster-admin credential. |
| `context-file` | No | — | Path to the `kaaval.yaml` risk context (risk context as code). |
| `fail-on-score` | No | — | Fail the job if any finding's contextual score is `>=` this value. |
| `fail-on-severity` | No | — | Fail the job if any finding is at/above this severity (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`). |
| `output` | No | `table` | Output format: `table` or `json`. |
| `kaaval-ref` | No | `main` | Git ref of Kaaval to run — pin this for reproducible CI runs. |

Provide `manifests` for shift-left scanning, or `kubeconfig` for a live
cluster — not both. Combine `fail-on-score` and/or `fail-on-severity` to gate
the job; with neither set, the action reports findings without failing the
build.
