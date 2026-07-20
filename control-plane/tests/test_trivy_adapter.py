import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app import trivy_adapter

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "trivy_report_sample.json"


@pytest.fixture
def sample_report():
    return json.loads(FIXTURE_PATH.read_text())


def _fake_score(cvss_score, severity, context):
    """Deterministic stand-in for compute_contextual_score in tests."""
    base = cvss_score if cvss_score is not None else 0.0
    return base, {"cvss_score": base, "severity": severity}


def _fake_remediation(finding):
    """Deterministic stand-in for build_remediation in tests."""
    return f"Upgrade findings for {finding['cve_id']}"


@pytest.fixture(autouse=True)
def mocked_scoring():
    with patch.object(
        trivy_adapter, "compute_contextual_score", side_effect=_fake_score
    ) as score_mock, patch.object(
        trivy_adapter, "build_remediation", side_effect=_fake_remediation
    ) as remediation_mock:
        yield score_mock, remediation_mock


class TestTrivyAdapterParse:
    def test_empty_report_returns_empty_list(self):
        assert trivy_adapter.parse({}) == []
        assert trivy_adapter.parse(None) == []

    def test_maps_core_fields(self, sample_report):
        findings = trivy_adapter.parse(sample_report)
        by_cve = {f["cve_id"]: f for f in findings}

        f = by_cve["CVE-2023-0286"]
        assert f["title"].startswith("openssl: X.400 address type confusion")
        assert f["severity"] == "HIGH"
        assert f["cvss_score"] == 7.4
        assert f["affected"] == [
            {
                "component": "openssl",
                "version": "1.1.1n-0+deb11u4",
                "fixed": "1.1.1n-0+deb11u5",
            }
        ]
        assert f["fixed_in"] == ["1.1.1n-0+deb11u5"]
        assert f["references"][:1] == [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-0286"
        ]
        assert len(f["references"]) <= 3

    def test_additive_source_and_image_fields(self, sample_report):
        findings = trivy_adapter.parse(sample_report)
        for f in findings:
            assert f["source"] == "trivy"
            assert f["image"] == "myregistry.io/payments-api:1.4.2"

    def test_dedup_by_cve_image_component_across_results(self, sample_report):
        # CVE-2023-0286/openssl appears in both Results[0] and Results[1]
        # (os-pkgs and lang-pkgs targets) — must collapse to one finding.
        findings = trivy_adapter.parse(sample_report)
        matches = [f for f in findings if f["cve_id"] == "CVE-2023-0286"]
        assert len(matches) == 1

    def test_missing_fixed_version_yields_none_fixed_and_null_fixed_in(
        self, sample_report
    ):
        findings = trivy_adapter.parse(sample_report)
        curl_finding = next(f for f in findings if f["cve_id"] == "CVE-2022-1234")
        assert curl_finding["affected"][0]["fixed"] is None
        assert curl_finding["fixed_in"] is None

    def test_missing_cvss_yields_none_score(self, sample_report):
        findings = trivy_adapter.parse(sample_report)
        curl_finding = next(f for f in findings if f["cve_id"] == "CVE-2022-1234")
        assert curl_finding["cvss_score"] is None

    def test_severity_is_upper_cased(self, sample_report):
        findings = trivy_adapter.parse(sample_report)
        zlib_finding = next(f for f in findings if f["cve_id"] == "CVE-2021-9999")
        assert zlib_finding["severity"] == "UNKNOWN"

    def test_missing_title_falls_back_to_cve_and_package(self, sample_report):
        findings = trivy_adapter.parse(sample_report)
        curl_finding = next(f for f in findings if f["cve_id"] == "CVE-2022-1234")
        assert curl_finding["title"] == "CVE-2022-1234: curl"

    def test_description_is_truncated_to_500_chars(self, sample_report):
        report = json.loads(FIXTURE_PATH.read_text())
        long_desc = "x" * 900
        report["Results"][0]["Vulnerabilities"][0]["Description"] = long_desc
        findings = trivy_adapter.parse(report)
        f = next(f for f in findings if f["cve_id"] == "CVE-2023-0286")
        assert len(f["description"]) == 500

    def test_scoring_and_remediation_are_attached(self, sample_report):
        findings = trivy_adapter.parse(sample_report)
        for f in findings:
            assert "contextual_score" in f
            assert "score_factors" in f
            assert f["remediation"] == f"Upgrade findings for {f['cve_id']}"

    def test_results_sorted_by_contextual_score_descending(self, sample_report):
        findings = trivy_adapter.parse(sample_report)
        scores = [f["contextual_score"] for f in findings]
        assert scores == sorted(scores, reverse=True)

    def test_context_is_forwarded_to_compute_contextual_score(
        self, sample_report, mocked_scoring
    ):
        score_mock, _ = mocked_scoring
        context = {"environment": "production", "compliance": ["pci"]}
        trivy_adapter.parse(sample_report, context=context)
        for call in score_mock.call_args_list:
            assert call.args[2] == context

    def test_default_context_is_empty_dict(self, sample_report, mocked_scoring):
        score_mock, _ = mocked_scoring
        trivy_adapter.parse(sample_report)
        for call in score_mock.call_args_list:
            assert call.args[2] == {}

    def test_no_vulnerabilities_key_is_treated_as_empty(self):
        report = {
            "ArtifactName": "some/image:latest",
            "Results": [{"Target": "some/image:latest (debian)", "Class": "os-pkgs"}],
        }
        assert trivy_adapter.parse(report) == []

    def test_entry_missing_vulnerability_id_or_pkg_name_is_skipped(self):
        report = {
            "ArtifactName": "some/image:latest",
            "Results": [
                {
                    "Vulnerabilities": [
                        {"PkgName": "openssl", "InstalledVersion": "1.0"},
                        {"VulnerabilityID": "CVE-2024-0001"},
                    ]
                }
            ],
        }
        assert trivy_adapter.parse(report) == []