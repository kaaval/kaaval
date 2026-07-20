"""
Pure adapter: Trivy `trivy image --format json` (schema v2) -> Kaaval finding shape.

parse(report_json) -> list[finding_dict]

Emits the exact shape `cve_service._match_cves()` produces so everything
downstream (compute_contextual_score, build_remediation, PDF builder,
dashboard) works unmodified. Two additive fields are appended on top of the
native shape: `source` and `image` (see docs/trivy-grype-integration.md).

This module has no side effects and does no I/O — it is a pure transform
from a parsed JSON dict to a list of finding dicts, so it can be unit
tested without a database or a running Trivy binary.
"""
from __future__ import annotations

from typing import Any, Optional

from app.scoring import compute_contextual_score
from app.remediation import build_remediation

SOURCE_NAME = "trivy"


def _severity(raw: Optional[str]) -> str:
    """Upper-case the severity, defaulting to UNKNOWN when absent."""
    if not raw:
        return "UNKNOWN"
    return str(raw).upper()


def _best_cvss_score(vuln: dict) -> Optional[float]:
    """
    Return the highest CVSS v3 base score present across all vendors Trivy
    reports (nvd, redhat, ghsa, ...), or None if no v3 score is present.
    """
    cvss = vuln.get("CVSS") or {}
    scores = []
    for _vendor, data in cvss.items():
        if not isinstance(data, dict):
            continue
        score = data.get("V3Score")
        if isinstance(score, (int, float)):
            scores.append(float(score))
    return max(scores) if scores else None


def _title(vuln: dict, cve_id: str, pkg_name: str) -> str:
    title = vuln.get("Title")
    if title:
        return title
    return f"{cve_id}: {pkg_name}"


def _references(vuln: dict) -> list:
    refs = vuln.get("References") or []
    return refs[:3]


def parse(report_json: dict, context: Optional[dict] = None) -> list[dict]:
    """
    Convert a parsed Trivy JSON report (schema v2, from
    `trivy image --format json`) into a list of Kaaval finding dicts.

    Findings are deduped on (cve_id, image, component) — the same CVE
    matching the same package inside the same image target is one
    finding, even if it shows up under multiple `Results[]` entries
    (e.g. reported against both an OS package layer and a lockfile scan
    of the same artifact).

    `context` is the tenant's existing ScanContext (same one passed to the
    native scanner's `compute_contextual_score()` call) — pass it through
    so ingested findings are scored with the same production/PCI/etc.
    context as native findings. Defaults to an empty context.
    """
    if not report_json:
        return []

    scan_context = context or {}

    image = report_json.get("ArtifactName", "unknown")
    results = report_json.get("Results") or []

    # component -> merged affected_matches, keyed by (cve_id, component)
    merged: dict[tuple, dict] = {}

    for result in results:
        vulnerabilities = result.get("Vulnerabilities") or []
        for vuln in vulnerabilities:
            cve_id = vuln.get("VulnerabilityID")
            pkg_name = vuln.get("PkgName")
            if not cve_id or not pkg_name:
                # Nothing to key a finding on — skip malformed entries.
                continue

            component = pkg_name.lower()
            dedup_key = (cve_id, image, component)

            affected_entry = {
                "component": component,
                "version": vuln.get("InstalledVersion"),
                "fixed": vuln.get("FixedVersion") or None,
            }

            if dedup_key in merged:
                # Same CVE/image/component seen again (e.g. from another
                # Results[] target) — keep the first record, nothing to add
                # since it's the same component.
                continue

            fixed_version = vuln.get("FixedVersion") or None

            finding = {
                "cve_id": cve_id,
                "title": _title(vuln, cve_id, pkg_name),
                "severity": _severity(vuln.get("Severity")),
                "cvss_score": _best_cvss_score(vuln),
                "affected": [affected_entry],
                "fixed_in": [fixed_version] if fixed_version else None,
                "description": (vuln.get("Description") or "")[:500],
                "references": _references(vuln),
                "published_date": vuln.get("PublishedDate"),
                "source": SOURCE_NAME,
                "image": image,
            }

            contextual_score, score_factors = compute_contextual_score(
                finding["cvss_score"], finding["severity"], scan_context
            )
            finding["contextual_score"] = contextual_score
            finding["score_factors"] = score_factors
            finding["remediation"] = build_remediation(finding)

            merged[dedup_key] = finding

    findings = list(merged.values())
    findings.sort(key=lambda f: -f["contextual_score"])
    return findings