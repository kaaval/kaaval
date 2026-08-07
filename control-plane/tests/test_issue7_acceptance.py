"""
Re-runnable acceptance test for kaaval#7 (CIS 5.1.6 token_automount rule).

Moved here from the standalone `check_issue7_acceptance.py` script per
@rrskris's PR #108 review: this now runs in CI (pytest) instead of only when
someone remembers to run the script by hand. Token findings are the first
findings with no `role`/`binding`, so the 5-output-mode regression below is a
real guard against a SARIF/JUnit/PolicyReport builder crashing on them.
"""
import json
import subprocess
import sys
import pathlib

import pytest

_CP = pathlib.Path(__file__).parent.parent
_FIXTURES = str(_CP.parent / "hack/dev/rbac-fixtures.yaml")


def _run_scan(output_mode: str):
    return subprocess.run(
        [sys.executable, "-m", "app.cli", "scan", "rbac",
         "--manifests", _FIXTURES, "--output", output_mode],
        capture_output=True, text=True, cwd=_CP,
    )


def test_issue7_token_automount_severities():
    result = _run_scan("json")
    data = json.loads(result.stdout)
    automount_findings = [f for f in data["findings"] if f["rule_type"] == "token_automount"]

    severity_by_name = {
        (f.get("workload") or f["service_account"])["name"]: f["severity"]
        for f in automount_findings
    }
    assert set(severity_by_name) == {"default", "token-happy", "override-pod", "override-deploy"}, severity_by_name
    assert severity_by_name == {
        "default": "MEDIUM",
        "token-happy": "LOW",
        "override-pod": "MEDIUM",
        "override-deploy": "MEDIUM",
    }, severity_by_name

    kinds = {(f.get("workload") or {}).get("kind") for f in automount_findings if f.get("workload")}
    assert kinds == {"Pod", "Deployment"}, kinds


@pytest.mark.parametrize("output_mode", ["table", "json", "sarif", "junit", "policyreport"])
def test_issue7_all_output_modes_survive_token_findings(output_mode):
    result = _run_scan(output_mode)
    assert result.returncode == 0, (
        f"--output {output_mode} exited {result.returncode}: {result.stderr[-200:]}"
    )
