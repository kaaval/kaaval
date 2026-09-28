"""Report import must score real-shaped data, fail closed, and isolate tenants."""

import io
import json
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import cli, models
from app.auth import get_current_active_user
from app.database import get_db
from app.main import app

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(params=["trivy", "grype"])
def report(request):
    source = request.param
    return source, json.loads((FIXTURES / f"{source}_report_sample.json").read_text())


def test_cli_same_report_changes_rank_and_gate_with_context(report, tmp_path, capsys):
    source, raw = report
    path = tmp_path / "report.json"
    path.write_text(json.dumps(raw))
    context = tmp_path / "kaaval.yaml"
    args = ["scan", "image", f"--from-{source}", str(path), "--context-file", str(context),
            "--output", "json", "--fail-on-score", "10"]
    context.write_text("environment: dev\ndata_classification: public\n")
    assert cli.main(args) == 0
    dev = json.loads(capsys.readouterr().out)
    context.write_text("environment: production\ndata_classification: pii\nexposure: internet-facing\ncompliance_scope: [PCI-DSS]\n")
    assert cli.main(args) == 1
    prod = json.loads(capsys.readouterr().out)
    assert dev["affected_count"] == prod["affected_count"] == 4
    assert [f["cve_id"] for f in dev["findings"]] == [f["cve_id"] for f in prod["findings"]]
    assert prod["findings"][0]["contextual_score"] > dev["findings"][0]["contextual_score"]
    assert all(f["source"] == source and f["remediation"]["action"] for f in prod["findings"])


@pytest.mark.parametrize("output", ["json", "table", "sarif", "junit", "policyreport"])
def test_image_exporters_use_image_identity(report, output, monkeypatch, capsys):
    source, raw = report
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(raw).encode())))
    assert cli.main(["scan", "image", f"--from-{source}", "-", "--output", output]) == 0
    text = capsys.readouterr().out
    assert "ServiceAccount/None" not in text
    if output == "json":
        assert json.loads(text)["affected_count"] == 4
    elif output == "sarif":
        run = json.loads(text)["runs"][0]
        assert len(run["results"]) == 4
        assert all(r["ruleId"].startswith("CVE-") for r in run["results"])
        assert "payments-api" in run["results"][0]["locations"][0]["logicalLocations"][0]["name"]
    elif output == "junit":
        suite = ET.fromstring(text)
        assert suite.attrib["name"] == "kaaval.image"
        assert suite.attrib["failures"] == "4"
    elif output == "policyreport":
        documents = list(yaml.safe_load_all(text))
        assert len(documents) == 1
        assert documents[0]["metadata"]["name"] == "kaaval-image"
        for result in documents[0]["results"]:
            assert "resources" not in result
            assert result["properties"]["scanner"] == source
            assert "payments-api" in result["properties"]["image"]
    else:
        assert "Kaaval image scan" in text
        assert "payments-api" in text


@pytest.mark.parametrize("raw", [b"", b"{bad", b"null", b"[]", b"{}",
    b'{"matches":[]}', b'{"SchemaVersion":2,"ArtifactName":"x","ArtifactType":"container_image","Results":[null]}'])
def test_cli_rejects_bad_reports_with_usage_exit(raw, tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", "image", "--from-trivy", str(path), "--output", "json"])
    assert exc.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "invalid trivy image report" in output.err


def test_missing_and_oversized_reports_fail_closed(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    args = ["scan", "image", "--from-trivy", str(path)]
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    assert exc.value.code == 2
    monkeypatch.setenv("KAAVAL_MAX_REQUEST_BODY_MB", "1")
    path.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    assert exc.value.code == 2


def test_real_cli_pipe_exit_and_clean_report():
    raw = {"SchemaVersion": 2, "ArtifactName": "clean:1", "ArtifactType": "container_image"}
    completed = subprocess.run(
        [sys.executable, "-m", "app.cli", "scan", "image", "--from-trivy", "-", "--output", "junit"],
        input=json.dumps(raw), text=True, capture_output=True, timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    suite = ET.fromstring(completed.stdout)
    assert suite.attrib["tests"] == "1"
    assert suite.attrib["failures"] == "0"


@pytest.mark.parametrize("flag,value", [("--fail-on-score", "nan"), ("--fail-on-score", "-1"),
    ("--fail-on-score", "inf"), ("--fail-on-severity", "typo")])
def test_invalid_gate_cannot_silently_pass(flag, value):
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", "image", "--from-trivy", "unused.json", flag, value])
    assert exc.value.code == 2


@pytest.fixture
def api():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    models.Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    tenants = [uuid.uuid4(), uuid.uuid4()]
    for tenant in tenants:
        db.add(models.Tenant(id=tenant, name=str(tenant)))
    db.flush()
    db.add(models.ScanContext(tenant_id=tenants[0], environment="dev", data_classification="public"))
    db.add(models.ScanContext(tenant_id=tenants[1], environment="production", data_classification="phi",
                             exposure="internet-facing", compliance_scope=["HIPAA"]))
    db.commit()
    current = SimpleNamespace(tenant_id=tenants[0])
    saved = app.dependency_overrides.copy()
    app.dependency_overrides[get_current_active_user] = lambda: current
    app.dependency_overrides[get_db] = lambda: db
    try:
        yield TestClient(app), db, current, tenants
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved)
        db.close()
        engine.dispose()


def test_api_persists_context_and_isolates_latest_scan(api, report):
    client, db, user, tenants = api
    source, raw = report
    assert client.get("/ingest/scans/latest").status_code == 404
    first = client.post(f"/ingest/{source}", json=raw)
    assert first.status_code == 201, first.text
    first = first.json()
    assert first["affected_count"] == 4
    user.tenant_id = tenants[1]
    assert client.get("/ingest/scans/latest").status_code == 404
    second = client.post(f"/ingest/{source}", json=raw).json()
    assert second["findings"][0]["contextual_score"] > first["findings"][0]["contextual_score"]
    assert second["id"] != first["id"]
    user.tenant_id = tenants[0]
    assert client.get("/ingest/scans/latest", params={"source": source}).json() == first
    other = "grype" if source == "trivy" else "trivy"
    assert client.get("/ingest/scans/latest", params={"source": other}).status_code == 404
    assert db.query(models.IngestedScanResult).count() == 2


def test_api_authenticates_before_reading_body():
    response = TestClient(app).post("/ingest/trivy", content=b"not json")
    assert response.status_code == 401


def test_invalid_and_oversized_api_reports_are_not_persisted(api, monkeypatch, report):
    client, db, _, _ = api
    source, raw = report
    monkeypatch.setenv("KAAVAL_MAX_REQUEST_BODY_MB", "1")
    assert client.post(f"/ingest/{source}", json={}).status_code == 422
    assert client.post(f"/ingest/{source}", content=b"").status_code == 422
    response = client.post(f"/ingest/{source}", content=(b" " * 1024 for _ in range(1025)))
    assert response.status_code == 413
    if source == "trivy":
        raw["Results"][0]["Vulnerabilities"][0]["CVSS"]["nvd"]["V3Score"] = 99
    else:
        raw["matches"][0]["vulnerability"]["cvss"][0]["metrics"]["baseScore"] = 99
    assert client.post(f"/ingest/{source}", json=raw).status_code == 422
    assert db.query(models.IngestedScanResult).count() == 0


def test_report_openapi_has_no_dangling_local_definitions():
    spec = app.openapi()
    for source in ("trivy", "grype"):
        schema = spec["paths"][f"/ingest/{source}"]["post"]["requestBody"]["content"]["application/json"]["schema"]
        assert "#/$defs/" not in json.dumps(schema)
        assert schema["type"] == "object"


def _scan_shared_cve(output, monkeypatch, capsys):
    raw = (FIXTURES / "trivy_report_shared_cve.json").read_bytes()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw)))
    assert cli.main(["scan", "image", "--from-trivy", "-", "--output", output]) == 0
    return capsys.readouterr().out


def test_junit_names_distinguish_packages_sharing_a_cve(monkeypatch, capsys):
    suite = ET.fromstring(_scan_shared_cve("junit", monkeypatch, capsys))
    cases = suite.findall("testcase")
    title = "openssl: X.400 address type confusion in X.400 GeneralName"

    assert suite.attrib["name"] == "kaaval.image"
    assert [c.attrib["classname"] for c in cases] == ["kaaval.image.CVE-2023-0286"] * 2
    assert sorted(c.attrib["name"] for c in cases) == [
        f"{title} [myregistry.io/payments-api:1.4.2 libssl1.1@1.1.1n-0+deb11u4]",
        f"{title} [myregistry.io/payments-api:1.4.2 openssl@1.1.1n-0+deb11u4]",
    ]


def test_junit_clean_image_scan_keeps_one_passing_testcase(monkeypatch, capsys):
    clean = {"SchemaVersion": 2, "ArtifactName": "myregistry.io/clean:1", "ArtifactType": "container_image",
             "Results": [{"Target": "myregistry.io/clean:1", "Vulnerabilities": []}]}
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(clean).encode())))
    assert cli.main(["scan", "image", "--from-trivy", "-", "--output", "junit"]) == 0
    suite = ET.fromstring(capsys.readouterr().out)
    cases = suite.findall("testcase")

    assert suite.attrib["name"] == "kaaval.image" and suite.attrib["failures"] == "0"
    assert len(cases) == 1 and cases[0].find("failure") is None


def test_rbac_junit_names_are_unchanged(capsys):
    fixtures = Path(__file__).resolve().parents[2] / "hack" / "dev" / "rbac-fixtures.yaml"
    assert cli.main(["scan", "rbac", "--manifests", str(fixtures), "--output", "json"]) == 0
    titles = sorted(f["title"] for f in json.loads(capsys.readouterr().out)["findings"])
    assert cli.main(["scan", "rbac", "--manifests", str(fixtures), "--output", "junit"]) == 0
    names = sorted(c.attrib["name"] for c in ET.fromstring(capsys.readouterr().out).findall("testcase"))
    assert names == titles
