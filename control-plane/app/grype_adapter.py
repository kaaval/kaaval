"""
Pure adapter: Grype `grype -o json` output -> Kaaval finding shape.

parse(report_json, context=None) -> list[finding_dict]

Mirrors trivy_adapter.py exactly: emits the same finding shape
`cve_service._match_cves()` produces, so everything downstream
(compute_contextual_score, build_remediation, PDF builder, dashboard)
works unmodified. The only difference from the Trivy adapter is the
source: "grype" tag and the input JSON structure being consumed
(matches[].vulnerability / .artifact / .fix instead of
Results[].Vulnerabilities[]).

This module has no side effects and does no I/O — a pure transform
from a parsed JSON dict to a list of finding dicts, testable without
a database or a running Grype binary.
"""
from __future__ import annotations

from typing import Optional

from app.scoring import compute_contextual_score
from app.remediation import build_remediation

SOURCE_NAME = "grype"


def _severity(raw: Optional[str]) -> str:
    """Upper-case the severity, defaulting to UNKNOWN when absent.

    Grype reports severity in Title-case ("High", "Critical", ...),
    unlike Trivy's already-upper-case values — both normalize to the
    same upper-case convention here.
    """
    if not raw:
        return "UNKNOWN"
    return str(raw).upper()


def _best_cvss_score(vulnerability: dict) -> Optional[float]:
    """
    Return the highest CVSS v3 base score present, or None if absent.

    Grype's cvss array can mix v2/v3 metrics from different sources.
    We skip v2 entries — v2 and v3 use different scales and must not
    be compared directly (v2 inflates many scores vs v3).
    Entries with no version key are included deliberately: under-reporting
    a CVE score is worse than over-reporting for a scanner.
    """
    cvss_entries = vulnerability.get("cvss") or []
    scores = []
    for entry in cvss_entries:
        if not isinstance(entry, dict):
            continue
        version = str(entry.get("version") or "")
        # Skip v2 scores — different scale, inflates vs v3.
        # Missing version key: include (under-reporting is worse).
        if version and not version.startswith("3"):
            continue
        metrics = entry.get("metrics") or {}
        score = metrics.get("baseScore")
        if isinstance(score, (int, float)):
            scores.append(float(score))
    return max(scores) if scores else None


def _title(vulnerability: dict, cve_id: str, pkg_name: str) -> str:
    # Grype doesn't provide a distinct "Title" field the way Trivy does —
    # fall back to "<cve_id>: <PkgName>" the same way Trivy does when its
    # Title is absent, for consistent finding titles across sources.
    return f"{cve_id}: {pkg_name}"


def _references(vulnerability: dict) -> list:
    refs = vulnerability.get("urls") or []
    return refs[:3]


def _image_name(report_json: dict) -> str:
    source = report_json.get("source") or {}
    target = source.get("target")
    if isinstance(target, dict):
        return target.get("userInput") or target.get("imageID") or "unknown"
    if isinstance(target, str):
        return target
    return "unknown"


def parse(report_json: dict, context: Optional[dict] = None) -> list[dict]:
    """
    Convert a parsed Grype JSON report (from `grype -o json`) into a list
    of Kaaval finding dicts.

    Findings are deduped on (cve_id, image, component) — same rule as
    the Trivy adapter — because the same CVE affecting the same
    component in two images needs two separate rebuilds.

    `context` is the tenant's existing ScanContext, forwarded to
    compute_contextual_score() exactly as in the Trivy adapter. Defaults
    to an empty context.
    """
    if not report_json:
        return []

    scan_context = context or {}
    image = _image_name(report_json)
    matches = report_json.get("matches") or []

    merged: dict[tuple, dict] = {}

    for match in matches:
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}

        cve_id = vulnerability.get("id")
        pkg_name = artifact.get("name")
        if not cve_id or not pkg_name:
            # Nothing to key a finding on — skip malformed entries.
            continue

        component = pkg_name.lower()
        dedup_key = (cve_id, image, component)

        if dedup_key in merged:
            continue

        fix = vulnerability.get("fix") or {}
        fix_versions = fix.get("versions") or []
        fixed_version = fix_versions[0] if fix_versions else None

        affected_entry = {
            "component": component,
            "version": artifact.get("version"),
            "fixed": fixed_version,
        }

        finding = {
            "cve_id": cve_id,
            "title": _title(vulnerability, cve_id, pkg_name),
            "severity": _severity(vulnerability.get("severity")),
            "cvss_score": _best_cvss_score(vulnerability),
            "affected": [affected_entry],
            "fixed_in": [fixed_version] if fixed_version else None,
            "description": (vulnerability.get("description") or "")[:500],
            "references": _references(vulnerability),
            "published_date": None,  # Grype does not surface a published date.
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