# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Project renamed: Argus → Kaaval** (కావల్, "guard duty / keeping watch") to avoid
  colliding with the long-running openargus.org network audit project. Repo is now
  `github.com/kaaval/kaaval`, images are `ghcr.io/kaaval/kaaval` and
  `ghcr.io/kaaval/kaaval-dashboard`, env vars are `KAAVAL_*` (were `ARGUS_*`), the
  GitHub Action lives at `.github/actions/kaaval-scan`, and the CLI context file is
  `kaaval.yaml`. Old GitHub URLs redirect; old `argus-k8s` images stay up but frozen.
- Container images now publish to GHCR on every push to `main` (`:edge`, `:sha-*`)
  and on `v*` tags.
- Container entrypoint dispatches: `docker run … scan rbac …` runs the headless CLI,
  no arguments (or `serve`) runs the API server.

### Added
- **Trivy report ingestion** (`app/trivy_adapter.py`): a pure
  `parse(report_json, context) -> list[finding_dict]` adapter turning
  `trivy image --format json` (schema v2) output into the same finding shape
  `cve_service._match_cves()` produces, so scoring, remediation, the PDF builder and
  the dashboard consume image-layer CVEs unmodified. Adds additive `source` and
  `image` fields; dedupes on `(cve_id, image, component)`. Contributed by
  [@Diyaaa-12](https://github.com/Diyaaa-12) (#106).
- **CIS 5.1.6 `token_automount` rule**: flags ServiceAccounts whose effective
  automount is on (unset/null/true — `default` SA at MEDIUM, others LOW) and pods that
  re-enable automount over an SA that explicitly opted out. Covers bare Pods plus the
  pod templates of Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs and
  CronJobs in `--manifests` mode. Contributed by
  [@donkk11](https://github.com/donkk11) (#108).
- **Combination-escalation predicates** (`app/effective_access.py`): the Effective
  Access Graph foundation. Aggregates every Role/ClusterRole rule a subject holds
  across all its bindings, then evaluates four predicates that only fire on the
  *combination* — `combo_role_escalation` (create roles + `escalate`),
  `combo_bind_escalation` (create rolebindings + `bind`), `impersonation_grant`
  (`impersonate` on users/groups/serviceaccounts), and `privileged_pod_creation`
  (create pods + a privileged ServiceAccount in the same namespace). Each half is
  harmless alone, so the per-role scan misses all four. Exposed as
  `POST /rbac/combo-scan`. Contributed by
  [@Maqbool61](https://github.com/Maqbool61) (#105).
- **Helm chart skeleton** (`deploy/helm/kaaval`): `Chart.yaml` with a real
  `postgresql` subchart dependency, a fully annotated `values.yaml` mapping each value
  to its `.env.example` key, and a `helm lint` + `helm template` CI job on
  SHA-pinned actions. Contributed by
  [@girosole60](https://github.com/girosole60) (#103).
- **`--version` flag and JUnit XML output** (`--output junit`): version is
  single-sourced from `app.__version__` (fixing the stale hardcoded API version),
  and findings emit as JUnit testcases for GitLab/Jenkins test panes — a clean
  scan emits one passing case instead of an empty suite. Contributed by
  [@donkk11](https://github.com/donkk11) (#81).
- **SARIF `security-severity`**: SARIF rules carry a `security-severity` scaled from
  the per-rule maximum Contextual Risk Score (capped by `MAX_CONTEXTUAL_SCORE`,
  derived from the scoring weight maxima), so GitHub's Security-tab ordering mirrors
  Kaaval's contextual ranking. Contributed by
  [@Diyaaa-12](https://github.com/Diyaaa-12) (#56).
- **Scheduled in-cluster scans**: `deploy/cronjob.yaml` runs the headless CLI on a
  schedule and applies findings as PolicyReport/ClusterPolicyReport documents —
  init-container scans, pinned-kubectl main container applies, minimal split
  ClusterRoles, hardened pod security context. Contributed by
  [@Maqbool61](https://github.com/Maqbool61) (#59).
- **PolicyReport output** (`--output policyreport`): findings emit as Kubernetes
  Policy WG `wgpolicyk8s.io/v1alpha2` PolicyReport/ClusterPolicyReport documents —
  one report per namespace plus a cluster report — with contextual score,
  remediation, and CIS refs in `properties`. Validated against the wg-policy CRDs
  in a live cluster and consumed by policy-reporter under `source: Kaaval`.
- Roadmap v2: every item tied to a labeled issue and a GitHub milestone
  (v1.2 / v1.3 / v2.0), plus an explicit "how this ladders to CNCF" section.
- RBAC misconfiguration scanning: 11 rules mapped to CIS Kubernetes Benchmark
  v1.12.0 §5.1, with per-finding remediation (kubectl command, why-it-matters,
  benchmark refs, compliance + audit notes).
- Contextual Risk Score engine shared by CVE and RBAC findings — environment, data
  classification, compliance scope, and exposure drive the ranking, with visible
  score factors.
- Headless CLI (`python -m app.cli scan rbac`) for CI/CD: manifests (shift-left) or
  live cluster, `--fail-on-score` / `--fail-on-severity` gating, JSON/table output,
  plus a composite GitHub Action.
- RBAC scan PDF export (`GET /rbac/scan/latest/report.pdf`).
- Kyverno admission-time counterparts of the RBAC rules (`policies/kyverno/`), with
  two policies staged for upstream contribution to `kyverno/policies`.
- Documentation set: architecture, API reference, RBAC rule catalog, contextual-risk
  score formula, CI integration, Trivy/Grype ingestion design.
- Project governance: GOVERNANCE.md, MAINTAINERS.md, ADOPTERS.md, full Contributor
  Covenant v2.1, DCO sign-off requirement, CHANGELOG.

### Fixed
- **RBAC scan diffs surface severity changes**: `GET /rbac/scan/diff` gained a
  `severity_changed` bucket, so a finding that escalates between scans no longer hides
  in `unchanged` — the diff keys on finding identity and compares severity separately.
  Contributed by [@floze-the-genius](https://github.com/floze-the-genius) (#100).
- **Scanner RBAC covers the token-automount inputs**: the `kaaval-scanner-reader`
  ClusterRole in `deploy/cronjob.yaml` and the role documented in
  `docs/ci-integration.md` now grant read on core `serviceaccounts` and `pods`. Without
  them the CIS 5.1.6 rule logged a warning and silently returned no findings in live
  mode for anyone following the documented deployment (#119).
- Documentation corrections found while verifying the above: the `--output` flag table
  omitted the long-shipped `sarif` and `junit` values, `docs/api.md` did not document
  `GET /rbac/scan/diff`, and `docs/ci-integration.md` claimed Kaaval would not flag its
  own scanner role — it does, and has since the `segmentation_violation` rule landed in
  #52, because a cluster-wide read genuinely requires a ClusterRoleBinding (#118, #119).
- CLI exits 2 with an actionable error when the `--manifests` path is missing or
  unreadable, instead of silently reporting a clean scan — `Path.rglob()` swallows
  `EACCES` during traversal, so unreadable directories previously produced a false
  exit 0. Regression tests exercise real chmod-000 conditions. Contributed by
  [@donkk11](https://github.com/donkk11) (#45).

### Removed
- The vestigial CE/EE license gate (`license.py`) and every "Enterprise tier"
  reference. Kaaval is fully open source with no feature gates, aligned with CNCF
  vendor-neutrality standards.

## [1.1.0] - 2026-07-06

First public release, at the time under the name **Argus**.

### Added
- Kubernetes CVE scanning: fingerprints the live cluster (control-plane version +
  running add-ons: ingress-nginx, coredns, metrics-server, CSI drivers) and matches
  against the Kubernetes official CVE feed, OSV, and NVD.
- CVE scan PDF reporting.
- Next.js dashboard (scan results, feed management, settings, login).
- Multi-cluster registration and comparison.
- CI: control-plane pytest against a real Postgres service container; dashboard
  lint + build.
- Apache-2.0 license.

### Removed
- All dead pre-launch "Pro-NDS" enterprise-console code (12 backend routers,
  13 dashboard pages) that called APIs which no longer existed.

[Unreleased]: https://github.com/kaaval/kaaval/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/kaaval/kaaval/releases/tag/v1.1.0
