"""
Table-driven tests for the audit-log parser (issue #93).

Fixtures are realistic apiserver audit events with names scrubbed, as the
issue asks ("grab real events from a kind cluster with audit logging
enabled, scrub names"). Run with:

    cd control-plane
    KAAVAL_ADMIN_PASSWORD=test-admin-password python -m pytest tests/test_audit_ingest.py -v
"""

import os

from app.audit_ingest import parse_audit_usage


# ── Valid events (real apiserver shape, scrubbed) ────────────────────────────

VALID_CREATE = (
    '{"verb":"create","user":{"username":"system:serviceaccount:payments:api"},'
    '"objectRef":{"resource":"secrets","namespace":"payments",'
    '"name":"db-creds"}}'
)

VALID_GET_NAMESPACED = (
    '{"verb":"get","user":{"username":"system:serviceaccount:payments:api"},'
    '"objectRef":{"resource":"configmaps","namespace":"payments",'
    '"name":"settings"}}'
)

VALID_LIST_CLUSTER = (
    '{"verb":"list","user":{"username":"system:serviceaccount:ops:reader"},'
    '"objectRef":{"resource":"nodes","namespace":""}}'
)

VALID_HUMAN_USER = (
    '{"verb":"update","user":{"username":"alice@example.com"},'
    '"objectRef":{"resource":"deployments","namespace":"web"}}'
)

# Unknown verb — still recorded (we surface what happened) but logged.
VALID_UNKNOWN_VERB = (
    '{"verb":"frobnicate","user":{"username":"system:serviceaccount:ops:reader"},'
    '"objectRef":{"resource":"pods","namespace":"ops"}}'
)

# Non-resource request (e.g. /healthz) — never recorded as usage.
NON_RESOURCE_REQUEST = (
    '{"verb":"get","user":{"username":"system:serviceaccount:ops:reader"},'
    '"objectRef":null}'
)


# ── Malformed / incomplete ────────────────────────────────────────────────────

MALFORMED_JSON = '{"verb":"create", "user": <<< not json'

NON_OBJECT_LINE = "just a string, not a json object"

MISSING_USER = '{"verb":"get","objectRef":{"resource":"pods","namespace":"x"}}'

MISSING_USERNAME = (
    '{"verb":"get","user":{"uid":"abc123"},'
    '"objectRef":{"resource":"pods","namespace":"x"}}'
)

MISSING_VERB = (
    '{"user":{"username":"system:serviceaccount:ops:reader"},'
    '"objectRef":{"resource":"pods","namespace":"x"}}'
)


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_valid_event_extracts_verb_resource_namespace():
    usage = parse_audit_usage([VALID_CREATE])
    assert "system:serviceaccount:payments:api" in usage
    assert ("create", "secrets", "payments") in usage[
        "system:serviceaccount:payments:api"
    ]


def test_same_subject_multiple_events_aggregate_into_one_set():
    usage = parse_audit_usage(
        [VALID_CREATE, VALID_GET_NAMESPACED, VALID_LIST_CLUSTER]
    )
    # Two subjects total.
    assert set(usage) == {
        "system:serviceaccount:payments:api",
        "system:serviceaccount:ops:reader",
    }
    payments = usage["system:serviceaccount:payments:api"]
    assert ("create", "secrets", "payments") in payments
    assert ("get", "configmaps", "payments") in payments
    # Cluster-scoped (empty namespace) is preserved as "".
    assert ("list", "nodes", "") in usage["system:serviceaccount:ops:reader"]


def test_human_username_subject_key_is_used():
    usage = parse_audit_usage([VALID_HUMAN_USER])
    assert "alice@example.com" in usage
    assert ("update", "deployments", "web") in usage["alice@example.com"]


def test_unknown_verb_is_still_recorded():
    usage = parse_audit_usage([VALID_UNKNOWN_VERB])
    assert ("frobnicate", "pods", "ops") in usage["system:serviceaccount:ops:reader"]


def test_non_resource_request_is_not_recorded_as_usage():
    usage = parse_audit_usage([NON_RESOURCE_REQUEST])
    assert usage == {}


def test_malformed_json_line_is_skipped_not_crashing():
    # A malformed line must not raise and must not pollute output.
    usage = parse_audit_usage([MALFORMED_JSON, VALID_GET_NAMESPACED])
    assert "system:serviceaccount:payments:api" in usage
    assert ("get", "configmaps", "payments") in usage[
        "system:serviceaccount:payments:api"
    ]


def test_non_object_line_is_skipped():
    usage = parse_audit_usage([NON_OBJECT_LINE, VALID_GET_NAMESPACED])
    assert "system:serviceaccount:payments:api" in usage


def test_missing_user_info_is_skipped():
    usage = parse_audit_usage([MISSING_USER, VALID_GET_NAMESPACED])
    assert "system:serviceaccount:payments:api" in usage


def test_missing_username_is_skipped():
    usage = parse_audit_usage([MISSING_USERNAME, VALID_GET_NAMESPACED])
    assert "system:serviceaccount:payments:api" in usage


def test_missing_verb_is_skipped():
    usage = parse_audit_usage([MISSING_VERB, VALID_GET_NAMESPACED])
    assert "system:serviceaccount:payments:api" in usage


def test_empty_input_yields_empty_dict():
    assert parse_audit_usage([]) == {}


def test_blank_lines_are_ignored():
    assert parse_audit_usage(["", "   ", "\n"]) == {}


def test_mixed_batch_keeps_valid_events_and_never_crashes():
    batch = [
        VALID_CREATE,
        MALFORMED_JSON,
        MISSING_USER,
        VALID_GET_NAMESPACED,
        NON_OBJECT_LINE,
        MISSING_VERB,
        VALID_LIST_CLUSTER,
        NON_RESOURCE_REQUEST,
    ]
    usage = parse_audit_usage(batch)
    # Only the 3 valid events contribute; the rest are skipped.
    assert set(usage) == {
        "system:serviceaccount:payments:api",
        "system:serviceaccount:ops:reader",
    }
    assert ("create", "secrets", "payments") in usage[
        "system:serviceaccount:payments:api"
    ]
    assert ("list", "nodes", "") in usage["system:serviceaccount:ops:reader"]


def test_accepts_file_like_iterable():
    import io

    f = io.StringIO("\n".join([VALID_CREATE, VALID_GET_NAMESPACED]))
    usage = parse_audit_usage(f)
    assert "system:serviceaccount:payments:api" in usage
    assert len(usage["system:serviceaccount:payments:api"]) == 2
