# Design: Trivy / Grype ingestion (external CVE finding sources)

**Status:** design proposal — no implementation yet.
**Decision needed:** approve the mapping + API shape below before building.

## Why

Kaaval's differentiation is not the detection engine — it's the layer on top:
the Contextual Risk Score and the per-finding remediation object (action /
why-it-matters / benchmark refs / compliance / audit note). Trivy and Grype
are excellent, ubiquitous image scanners; competing with them on CVE
*detection* would be feature-parity chasing. Letting Kaaval *ingest* their
output and score it turns them from competitors into feeds — the same
pattern already planned for Kyverno PolicyReports.

The native CVE scanner stays. Its zero-extra-tooling property (point Kaaval at
a cluster, get findings — no scanner install, no pipeline change) is a real
adoption differentiator, especially for the CE self-scan path. Ingestion is
strictly additive.

## What Trivy/Grype add that the native scanner doesn't

The native scanner matches *cluster and add-on versions* (control plane,
kubelet, ingress-nginx, coredns, …) against CVE feeds. Trivy/Grype scan
*container image contents* — OS packages and language dependencies inside
every workload image. Different level of the stack; near-zero overlap; both
belong in one ranked list, which is exactly what the shared scoring engine
is for.

## Input contract

Accept the tools' native JSON outputs, unmodified:

| Tool | Format | The parts we consume |
|---|---|---|
| Trivy | `trivy image --format json` (schema v2) | `Results[].Vulnerabilities[]`: `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `Severity`, `CVSS.*.V3Score`, `Title`, `Description`, `References`, plus `ArtifactName` for image identity |
| Grype | `grype -o json` | `matches[]`: `vulnerability.id`, `.severity`, `.cvss[].metrics.baseScore`, `.fix.versions`, `artifact.name`, `artifact.version`, `source.target` for image identity |

No new scanner config invented — if a team already runs Trivy or Grype in CI,
their existing JSON artifact is the integration.

## Mapping into the existing finding shape

One adapter per tool (`trivy_adapter.py`, `grype_adapter.py`), each a pure
function `parse(report_json) -> list[finding_dict]`, emitting the exact shape
`cve_service._match_cves()` already produces so **everything downstream works
unmodified** — `compute_contextual_score()`, `build_remediation()`, the PDF
builder, the dashboard row component:

```
{
  "cve_id":            VulnerabilityID / vulnerability.id
  "title":             Title (fallback: "<cve_id>: <PkgName>")
  "severity":          Severity upper-cased; UNKNOWN if absent
  "cvss_score":        highest v3 base score present, else None
  "affected":          [{"component": PkgName, "version": InstalledVersion,
                         "fixed": FixedVersion|None}]
  "fixed_in":          [FixedVersion] | None
  "description":       Description[:500]
  "references":        first 3
  "source":            "trivy" | "grype"        # NEW, additive field
  "image":             ArtifactName / source.target  # NEW, additive field
  "contextual_score":  computed at ingest via compute_contextual_score()
  "score_factors":     ditto
  "remediation":       built at ingest via build_remediation()
}
```

The two new fields (`source`, `image`) are additive; native findings simply
don't have them (same pattern as `contextual_score` was added without
breaking `severity`). `build_remediation()`'s CVE branch already produces
"Upgrade {component} to {fixed} or later" from this shape.

Dedup rule: `(cve_id, image, component)` — the same CVE in two images is two
findings, because the fix is two image rebuilds.

## API surface

```
POST /ingest/trivy   (body: raw trivy JSON, or {"reports": [...]})
POST /ingest/grype   (body: raw grype JSON)
GET  /ingest/scans/latest
```

- Auth: existing bearer auth, same as every other route.
- Persistence: new `IngestedScanResult` model, same shape/pattern as
  `RBACScanResult` (scanned_at, source, image_count, affected_count,
  findings JSON, status).
- Scoring context: the tenant's existing `ScanContext` — no new settings.
- Size guard: reject bodies > a configured limit (env var, default 20 MB);
  Trivy reports for large images are big.

CLI follow-up (work-stream E, later phase): `kaaval ingest trivy report.json
--fail-on-score N` gates a pipeline on *contextually scored* image findings —
Trivy's own `--severity HIGH` gate can't know the finding lands in a
production/PCI cluster.

## Non-goals

- Running Trivy/Grype for the user (no scanner orchestration; ingest only).
- Reachability analysis — Kubescape's territory; if ever added it becomes
  another score multiplier, not a separate verdict (see roadmap research).
- Replacing the native scanner (explicitly additive; see "Why").
- SBOM ingestion (CycloneDX/SPDX) — plausible later, out of scope here.

## Effort estimate

Small: two pure-function adapters + fixtures from real Trivy/Grype output,
one model, one router, ~1 session including tests — because scoring,
remediation, PDF, and dashboard are all reused as-is.
