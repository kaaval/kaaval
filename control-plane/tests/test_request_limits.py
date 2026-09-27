"""
Body-size guard for POST /rbac/combo-scan (issue #127).

The guard must reject an oversized body before the RBAC graph is parsed or
evaluated, whether the client declares Content-Length or streams the body.
No database needed: auth and the DB session are overridden.
"""

import json
import os

os.environ.setdefault("KAAVAL_ADMIN_PASSWORD", "test-admin-password")

import pytest
from fastapi.testclient import TestClient

from app.auth import get_current_active_user
from app.database import get_db
from app.main import app
from app.request_limits import DEFAULT_MAX_REQUEST_BODY_MB, max_request_body_bytes
from app.routers import rbac as rbac_router

MB = 1024 * 1024


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("KAAVAL_MAX_REQUEST_BODY_MB", "1")
    app.dependency_overrides[get_current_active_user] = lambda: object()
    app.dependency_overrides[get_db] = lambda: None
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(get_current_active_user, None)
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def evaluate_calls(monkeypatch):
    calls = []
    real = rbac_router.evaluate_combo_findings

    def _recording(graph, context):
        calls.append(graph)
        return real(graph, context)

    monkeypatch.setattr(rbac_router, "evaluate_combo_findings", _recording)
    return calls


def _oversized_body() -> bytes:
    # Valid JSON just over the 1 MB test limit.
    return json.dumps({"roles": [{"name": "x" * (MB + 10)}]}).encode()


def test_default_limit_is_20_mb(monkeypatch):
    monkeypatch.delenv("KAAVAL_MAX_REQUEST_BODY_MB", raising=False)
    assert DEFAULT_MAX_REQUEST_BODY_MB == 20
    assert max_request_body_bytes() == 20 * MB


def test_limit_is_configurable_by_env(monkeypatch):
    monkeypatch.setenv("KAAVAL_MAX_REQUEST_BODY_MB", "5")
    assert max_request_body_bytes() == 5 * MB


_CONTEXT = {"environment": "production", "data_classification": "internal", "exposure": "internal"}


def test_body_within_limit_is_evaluated(client, evaluate_calls):
    # Explicit context, so no stored tenant context is needed.
    resp = client.post("/rbac/combo-scan", json={"roles": [], "cluster_role_bindings": [], "context": _CONTEXT})
    assert resp.status_code == 200
    assert resp.json()["combo_findings_count"] == 0
    assert len(evaluate_calls) == 1


def test_oversized_body_with_content_length_is_rejected_before_evaluation(client, evaluate_calls):
    resp = client.post(
        "/rbac/combo-scan",
        content=_oversized_body(),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    assert "KAAVAL_MAX_REQUEST_BODY_MB" in resp.json()["detail"]
    assert evaluate_calls == []


def test_oversized_streamed_body_without_content_length_is_rejected(client, evaluate_calls):
    body = _oversized_body()

    def chunks():
        for i in range(0, len(body), 64 * 1024):
            yield body[i : i + 64 * 1024]

    resp = client.post(
        "/rbac/combo-scan",
        content=chunks(),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    assert evaluate_calls == []


def test_understated_content_length_is_still_caught_by_byte_count():
    # A client can send a small Content-Length and then stream more; the guard counts bytes.
    import asyncio

    from fastapi import HTTPException
    from starlette.requests import Request

    from app.request_limits import read_body_with_limit

    body = b"x" * 2048
    messages = [
        {"type": "http.request", "body": body[:1024], "more_body": True},
        {"type": "http.request", "body": body[1024:], "more_body": False},
    ]

    async def receive():
        return messages.pop(0)

    scope = {"type": "http", "method": "POST", "headers": [(b"content-length", b"10")]}
    with pytest.raises(HTTPException) as ctx:
        asyncio.run(read_body_with_limit(Request(scope, receive), limit=1500))
    assert ctx.value.status_code == 413


def test_invalid_body_is_a_clean_422_not_a_500(client, evaluate_calls):
    resp = client.post(
        "/rbac/combo-scan",
        content=b'{"roles": "not-a-list"}',
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422
    assert evaluate_calls == []

    resp = client.post(
        "/rbac/combo-scan",
        content=b"{not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422


def test_request_body_schema_still_documented():
    spec = app.openapi()
    schema = spec["paths"]["/rbac/combo-scan"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    if "$ref" in schema:
        schema = spec["components"]["schemas"][schema["$ref"].rsplit("/", 1)[1]]
    props = schema["properties"]
    assert {"roles", "cluster_roles", "role_bindings", "cluster_role_bindings", "context"} <= set(props)
