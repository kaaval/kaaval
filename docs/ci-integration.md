# CI/CD integration

Kaaval gates pipelines on the **Contextual Risk Score**, not a flat severity
threshold. The same wildcard ClusterRole that hard-fails a production/PCI
pipeline can pass with a warning in a dev pipeline — because the committed
risk context says so. Every scanner can `--fail-on HIGH`; this is the part
they can't do.

Two integration modes, one CLI:

- **Shift-left (`--manifests`)** — scan RBAC YAML in the repo (or
  `helm template` output) at PR time, before anything reaches a cluster. No
  cluster credentials needed.
- **Live (`--kubeconfig`)** — scan a real cluster's RBAC state, e.g. after a
  deploy or on a schedule, using a read-only CI service account.

Both run the exact same rule engine and scoring code the Kaaval server uses
(`evaluate_rbac_findings()` + `compute_contextual_score()` +
`build_remediation()`), with no database, auth, or running control plane.

## The CLI

```bash
cd control-plane
pip install -r requirements.txt

# shift-left: scan manifests in ./k8s
python -m app.cli scan rbac --manifests ./k8s/ \
    --context-file kaaval.yaml --fail-on-score 20 --output json

# live: scan the cluster a kubeconfig points at
python -m app.cli scan rbac --kubeconfig ./ci-kubeconfig --fail-on-severity HIGH
```

Or via the published container image (`ghcr.io/kaaval/kaaval` — no build, includes the CLI):

```bash
docker run --rm -v "$PWD/k8s:/scan" -v "$PWD/kaaval.yaml:/scan/kaaval.yaml" \
    ghcr.io/kaaval/kaaval \
    scan rbac --manifests /scan --context-file /scan/kaaval.yaml --fail-on-score 20
```

Tags: `latest` (newest release), `vX.Y.Z` (pinned release), `edge` (tip of main).

> **SELinux hosts (Fedora, RHEL, CentOS Stream):** add `:z` to each volume flag
> (`-v "$PWD/k8s:/scan:z"`) or the container is denied read access to the mount
> and the scan fails with a `PermissionError`.

### Flags

| Flag | Meaning |
|---|---|
| `--manifests PATH` | Scan RBAC YAML at PATH (file or directory, recursive; handles multi-doc YAML and `kind: List`) |
| `--kubeconfig PATH` | Scan the live cluster this kubeconfig points at (falls back to `$KUBECONFIG` / in-cluster / default kubeconfig if omitted) |
| `--context-file PATH` | `kaaval.yaml` risk context (see below). Without it, defaults apply (production/internal/internal, no compliance scope) and a warning is printed |
| `--fail-on-score N` | Exit 1 if any finding's contextual score ≥ N |
| `--fail-on-severity SEV` | Exit 1 if any finding is at/above SEV (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`, case-insensitive) |
| `--output table\|json\|policyreport` | Human table (default), full JSON including remediation objects and score factors, or Kubernetes [PolicyReport](https://github.com/kubernetes-sigs/wg-policy-prototypes/tree/master/policy-report) documents |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan ran; no finding at/above the configured thresholds (or no thresholds set) |
| 1 | Gate failed — at least one finding at/above a threshold |
| 2 | Usage error (bad path, invalid context value, bad flag) |

### `kaaval.yaml` — risk context as code

Commit this next to your manifests. It is the input to the scoring formula
(see [contextual-risk-score.md](contextual-risk-score.md)) and it is
reviewable in PRs like everything else:

```yaml
environment: production            # production | staging | dev
data_classification: pii           # public | internal | pii | financial | phi
compliance_scope: [PCI-DSS]        # any of PCI-DSS, HIPAA, SOC2 (or empty)
exposure: internet-facing          # internet-facing | internal
fail_on_score: 20                  # optional gate; CLI flags override
fail_on_severity: HIGH             # optional gate; CLI flags override
```

A sensible pattern: the dev overlay's `kaaval.yaml` says `environment: dev`
with a high (or no) threshold; the production overlay says
`environment: production` with a strict one. Same manifests, different gates
— by declared risk, not by pipeline copy-paste.

### Shift-left mode limitation

Findings are evaluated per (role, binding) pair. A binding that references a
role **not present in the scanned manifests** (e.g. the built-in
`cluster-admin` ClusterRole) is skipped in `--manifests` mode because there
are no rules to evaluate — live mode catches those, since the cluster knows
the role. Run both: manifests at PR time, live post-deploy.

## GitHub Actions

Use the composite action shipped in this repo:

```yaml
jobs:
  rbac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kaaval/kaaval/.github/actions/kaaval-scan@main
        with:
          manifests: k8s/
          context-file: k8s/kaaval.yaml
          fail-on-score: "20"
```

Inputs mirror the CLI flags (`manifests`, `kubeconfig`, `context-file`,
`fail-on-score`, `fail-on-severity`, `output`, plus `kaaval-ref` to pin an
Kaaval version). For live-cluster scans in CI, write the service-account
kubeconfig from a secret first:

```yaml
      - run: echo "${{ secrets.CI_KUBECONFIG }}" > ci-kubeconfig
      - uses: kaaval/kaaval/.github/actions/kaaval-scan@main
        with:
          kubeconfig: ci-kubeconfig
          context-file: kaaval.yaml
          fail-on-severity: CRITICAL
```

## GitLab CI

```yaml
kaaval-rbac-scan:
  stage: test
  image: python:3.12-slim
  script:
    - git clone --depth 1 https://github.com/kaaval/kaaval /kaaval
    - pip install -q -r /kaaval/control-plane/requirements.txt
    - cd /kaaval/control-plane
    - python -m app.cli scan rbac
        --manifests "$CI_PROJECT_DIR/k8s"
        --context-file "$CI_PROJECT_DIR/k8s/kaaval.yaml"
        --fail-on-score 20 --output json | tee "$CI_PROJECT_DIR/kaaval-report.json"
  artifacts:
    when: always
    paths: [kaaval-report.json]
```

## Jenkins (declarative)

```groovy
stage('Kaaval RBAC scan') {
    steps {
        sh '''
            git clone --depth 1 https://github.com/kaaval/kaaval kaaval
            pip install -q -r kaaval/control-plane/requirements.txt
            cd kaaval/control-plane
            python -m app.cli scan rbac \
                --manifests "$WORKSPACE/k8s" \
                --context-file "$WORKSPACE/k8s/kaaval.yaml" \
                --fail-on-score 20
        '''
    }
}
```

## Argo CD — verify after deploy (PostSync hook)

GitOps closes the loop with a live scan right after sync. The hook Job fails
the sync's health if the gate trips:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: kaaval-postsync-scan
  annotations:
    argocd.argoproj.io/hook: PostSync
    argocd.argoproj.io/hook-delete-policy: HookSucceeded
spec:
  template:
    spec:
      serviceAccountName: kaaval-scanner   # read-only RBAC viewer, see below
      restartPolicy: Never
      containers:
        - name: kaaval
          image: <your-registry>/kaaval-control-plane:latest
          command: ["python", "-m", "app.cli", "scan", "rbac",
                    "--fail-on-severity", "CRITICAL"]
```

Running in-cluster with a ServiceAccount needs only read access to RBAC
objects:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kaaval-scanner
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
    verbs: ["get", "list"]
```

(Yes — Kaaval's own scanner role is intentionally narrow enough that Kaaval
would not flag it.)

## Consuming the JSON in other tooling

`--output json` emits the full result: per-finding `contextual_score`,
`score_factors` (every multiplier, explained), and the `remediation` object
(`action`, `why_it_matters`, `benchmark_refs` with CIS Kubernetes Benchmark
v1.12.0 control IDs, `compliance_note`, `audit_note`). Pipe it to `jq`, post
it as a PR comment, or attach it as a build artifact — the explanation
travels with the finding.

## PolicyReport output (Kubernetes policy ecosystem)

`--output policyreport` emits findings as
[PolicyReport / ClusterPolicyReport](https://github.com/kubernetes-sigs/wg-policy-prototypes/tree/master/policy-report)
documents (`wgpolicyk8s.io/v1alpha2`) — the Kubernetes Policy WG standard that
[policy-reporter](https://kyverno.github.io/policy-reporter/), Kyverno, Falco,
and Trivy-operator all speak. One `PolicyReport` per namespace, one
`ClusterPolicyReport` for cluster-scoped findings; each result carries the
contextual score, remediation, and CIS refs in `properties`.

```bash
python -m app.cli scan rbac --kubeconfig ./kubeconfig --output policyreport \
    | kubectl apply -f -

kubectl get polr -A      # namespaced findings, PASS/FAIL columns
kubectl get cpolr        # cluster-scoped findings
```

Kaaval only *emits* the documents — applying them is your pipeline's explicit
step (shown above), so the scanner itself keeps its read-only contract. With
policy-reporter installed, Kaaval findings appear in its UI and API under
`source: Kaaval`, side by side with Kyverno and Falco results, and can fan out
to its notification targets (Slack, Teams, webhooks).

Planned next (see the roadmap): SARIF output for the GitHub Security tab,
JUnit XML for GitLab/Jenkins test panes, Prometheus metrics + scan-diff for
SRE alerting on *new* findings only, and a Helm chart for one-line install.

## GitHub Actions — SARIF upload to Security tab

```yaml
- name: Run Kaaval RBAC scan
  run: |
    python -m app.cli scan rbac \
      --manifests ./k8s/ \
      --context-file kaaval.yaml \
      --output sarif > results.sarif

- name: Upload SARIF to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

## Scheduled in-cluster scans (CronJob)

For continuous posture monitoring, deploy the CronJob manifest under `deploy/`
to run the headless CLI on a schedule and publish findings as PolicyReport
documents directly into your cluster.

### Prerequisites

The apply step needs the Policy WG `wgpolicyk8s.io` CRDs
(`PolicyReport`/`ClusterPolicyReport`) present in the cluster — without them
the Job fails with `no matches for kind "PolicyReport"`. Install either the
CRDs alone:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/wg-policy-prototypes/master/policy-report/crd/wgpolicyk8s.io/v1alpha2/wgpolicyk8s.io_policyreports.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/wg-policy-prototypes/master/policy-report/crd/wgpolicyk8s.io/v1alpha2/wgpolicyk8s.io_clusterpolicyreports.yaml
```

or [policy-reporter](https://kyverno.github.io/policy-reporter/) (or Kyverno),
which ships the CRDs and adds a UI for browsing the findings.

### Deploy

```bash
kubectl apply -f deploy/cronjob.yaml
```

This creates the `kaaval` namespace, a `kaaval-scanner` ServiceAccount with
a minimal read-only `ClusterRole` for RBAC objects, a `ClusterRole` with
write access to `policyreports`/`clusterpolicyreports`, and the CronJob
itself (scheduled daily at 02:00 UTC by default — edit `spec.schedule` to
taste).

### Trigger once (for testing)

```bash
kubectl create job --from=cronjob/kaaval-rbac-scan kaaval-rbac-scan-manual \
    -n kaaval
```

Watch it complete:

```bash
kubectl logs -n kaaval -l app.kubernetes.io/component=rbac-scanner -f
```

### Verify

```bash
kubectl get polr -A      # namespaced findings
kubectl get cpolr        # cluster-scoped findings
```

Fresh `PolicyReport` and `ClusterPolicyReport` objects appear under
`source: Kaaval`. If [policy-reporter](https://kyverno.github.io/policy-reporter/)
is installed, Kaaval findings show up in its UI alongside Kyverno and Falco
results automatically.

### Security context

The Pod runs as `nobody` (uid 65534), with a read-only root filesystem,
all Linux capabilities dropped, and `allowPrivilegeEscalation: false`. A
writable `emptyDir` is mounted at `/tmp` for Python's temporary files.

**SELinux hosts (Fedora, RHEL, CentOS Stream):** no extra volume flags are
needed because the Pod uses no host-path mounts — the ServiceAccount token
is a projected volume managed by the kubelet, which sets the correct SELinux
label automatically. If you see `PermissionError` on token reads, ensure
your kubelet version is ≥ 1.25 and the `seccompProfile: RuntimeDefault` in
the manifest is supported by your runtime.

### Customising the schedule and gate

Edit `spec.schedule` in `deploy/cronjob.yaml` for a different cadence, or
add `--fail-on-severity HIGH` / `--fail-on-score 20` to the `python -m app.cli`
command to make the Job exit 1 (and fail the CronJob run) when findings
breach your threshold — useful for alerting via `kubectl get jobs` or a
monitoring stack watching Job failure events.
