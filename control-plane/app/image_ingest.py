"""Validate external image reports before passing them to the pure adapters."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from . import grype_adapter, trivy_adapter
from .scoring import SEVERITY_ORDER


class ReportModel(BaseModel):
    model_config = ConfigDict(strict=True)


Score = Annotated[float, Field(ge=0, le=10, allow_inf_nan=False)]


class TrivyCVSS(ReportModel):
    V3Score: Score | None = None


class TrivyVulnerability(ReportModel):
    VulnerabilityID: Annotated[str, Field(min_length=1)]
    PkgName: Annotated[str, Field(min_length=1)]
    InstalledVersion: str | None = None
    FixedVersion: str | None = None
    Severity: str | None = None
    Title: str | None = None
    Description: str | None = None
    References: list[str] | None = None
    PublishedDate: str | None = None
    CVSS: dict[str, TrivyCVSS] | None = None


class TrivyResult(ReportModel):
    Vulnerabilities: list[TrivyVulnerability] | None = None


class TrivyReport(ReportModel):
    SchemaVersion: Literal[2]
    ArtifactName: Annotated[str, Field(min_length=1)]
    ArtifactType: Literal["container_image"]
    Results: list[TrivyResult] | None = None


class GrypeMetrics(ReportModel):
    baseScore: Score | None = None


class GrypeCVSS(ReportModel):
    version: str | None = None
    metrics: GrypeMetrics | None = None


class GrypeFix(ReportModel):
    versions: list[str] | None = None


class GrypeVulnerability(ReportModel):
    id: Annotated[str, Field(min_length=1)]
    severity: str | None = None
    cvss: list[GrypeCVSS] | None = None
    fix: GrypeFix | None = None
    description: str | None = None
    urls: list[str] | None = None


class GrypeArtifact(ReportModel):
    name: Annotated[str, Field(min_length=1)]
    version: str | None = None


class GrypeMatch(ReportModel):
    vulnerability: GrypeVulnerability
    artifact: GrypeArtifact


class GrypeTarget(ReportModel):
    userInput: str | None = None
    imageID: str | None = None


class GrypeSource(ReportModel):
    type: Literal["image"]
    target: GrypeTarget | str


class GrypeReport(ReportModel):
    matches: list[GrypeMatch]
    source: GrypeSource


REPORT_MODELS = {"trivy": TrivyReport, "grype": GrypeReport}


def score_report(report: TrivyReport | GrypeReport, context: dict) -> dict:
    source = "trivy" if isinstance(report, TrivyReport) else "grype"
    raw = report.model_dump(exclude_unset=True)
    adapter = trivy_adapter if source == "trivy" else grype_adapter
    findings = adapter.parse(raw, context)
    breakdown = {severity: 0 for severity in reversed(SEVERITY_ORDER)}
    for finding in findings:
        if finding["severity"] not in SEVERITY_ORDER:
            finding["severity"] = "UNKNOWN"
        breakdown[finding["severity"]] += 1
    image = raw["ArtifactName"] if source == "trivy" else grype_adapter._image_name(raw)
    return {
        "scan_type": "image", "mode": "report", "source": source,
        "image": image, "image_count": 1, "context": context,
        "affected_count": len(findings), "severity_breakdown": breakdown,
        "findings": findings,
    }
