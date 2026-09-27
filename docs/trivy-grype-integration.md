# Trivy / Grype image report ingestion

**Status:** CLI and authenticated API implemented. Dashboard import controls and
image-specific PDF export remain follow-ups.

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

## CLI: score existing reports

From `control-plane/` with the Python dependencies installed:

```bash
trivy image --format json --output report.json myregistry/payments:1.0
python -m app.cli scan image --from-trivy report.json --context-file kaaval.yaml --output json

grype myregistry/payments:1.0 -o json > grype.json
python -m app.cli scan image --from-grype grype.json --context-file kaaval.yaml --fail-on-score 20

set -o pipefail
trivy image --format json myregistry/payments:1.0 | python -m app.cli scan image --from-trivy - --output sarif
```

Use `--from-grype -` for Grype on stdin. The two source flags are mutually
exclusive. Kaaval reads an existing report; it never invokes a scanner itself.
Use `pipefail` so a scanner failure cannot be hidden by a later pipeline stage.

Outputs: `table`, `json`, `sarif`, `junit`, and `policyreport`. SARIF uses CVE IDs
and logical image locations. JUnit names the suite `kaaval.image`. PolicyReport
emits a `ClusterPolicyReport` named `kaaval-image`, with image/package identity
in string properties; it does not claim that an image is a Kubernetes resource.

Exit codes: `0` below threshold (or no gate), `1` at least one finding breaches
`--fail-on-score` or `--fail-on-severity`, `2` unreadable/invalid/oversized input
or invalid settings. Flags override the thresholds in the context file. With no
context file, the CLI warns and uses production/internal/internal defaults.

The same CVE, two contexts, using the bundled representative report fixture:

```bash
python -m app.cli scan image --from-trivy tests/fixtures/trivy_report_sample.json --context-file ../examples/image-ingest/dev.yaml --fail-on-score 10 --output json
python -m app.cli scan image --from-trivy tests/fixtures/trivy_report_sample.json --context-file ../examples/image-ingest/production.yaml --fail-on-score 10 --output json
```

Both reports contain the same four deduplicated findings. The dev invocation
passes; the production/PII/internet-facing invocation breaches the score gate.
The fixture is test data, not evidence that a particular live image is vulnerable.

## API: import and retrieve a tenant's report

| Route | Behavior |
|---|---|
| `POST /ingest/trivy` | Raw JSON from one Trivy image report; returns 201 with scored findings |
| `POST /ingest/grype` | Raw JSON from one Grype image report; returns 201 with scored findings |
| `GET /ingest/scans/latest?source=trivy` | Latest import for the authenticated tenant; optional source filter; 404 if none |

```bash
curl --fail-with-body -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' --data-binary @report.json http://localhost:8000/ingest/trivy
curl --fail-with-body -H "Authorization: Bearer $TOKEN" http://localhost:8000/ingest/scans/latest
```

Authentication runs before body parsing. The API uses the authenticated tenant's
stored `ScanContext` from `GET|PUT /cve/context`; a report cannot override it.
The stored response contains `id`, `scanned_at`, `source`, `image`, `image_count`,
`context`, `affected_count`, `severity_breakdown`, and `findings`. Latest-scan
queries always filter by tenant. Imports are stored in the new
`ingested_scan_results` table, created by the existing application startup schema
initialization; no existing scan data is rewritten.

Both entry points validate the report before scoring. Trivy requires schema v2,
`ArtifactType: container_image`, and `ArtifactName`; Grype requires `matches`
and an image `source`. Unknown metadata is ignored. Malformed finding records
and non-finite/out-of-range CVSS values are rejected rather than treated as a
clean scan. Batch envelopes such as `{"reports": [...]}` are not supported.

`KAAVAL_MAX_REQUEST_BODY_MB` sets the positive integer size limit (default 20 MB)
for API bodies and CLI reports. The API checks both Content-Length and streamed
bytes, returning 413 for excess size and 422 for invalid reports. The CLI reads
at most the limit plus one byte and exits 2 on excess size.

## Non-goals

- Running Trivy/Grype for the user (no scanner orchestration; ingest only).
- Reachability analysis — Kubescape's territory; if ever added it becomes
  another score multiplier, not a separate verdict (see roadmap research).
- Replacing the native scanner (explicitly additive; see "Why").
- SBOM ingestion (CycloneDX/SPDX) — plausible later, out of scope here.
