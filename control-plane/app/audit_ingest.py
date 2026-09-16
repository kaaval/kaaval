"""
Audit-log ingestion — file-based adapter (issue #93, part of #50).

Pure parser: input is an iterable of audit-log *lines* (JSON-lines, the
apiserver ``--audit-log-path`` format), output is a normalized usage set per
subject:

    parse_audit_usage(lines) -> dict[subject_key, set[tuple]]

where each tuple is ``(verb, resource, namespace)``.

This is the "used" side of the granted-vs-used least-privilege diff. It plugs
into the same ingestion seam the Trivy/Grype adapter uses and feeds the
Effective Access Graph (subject keys match #84/#92: the Kubernetes identity
string, i.e. ``user.username`` — e.g. ``system:serviceaccount:ns:sa`` or a
plain username).

Resilience contract (see tests/test_error_surfacing.py for the pattern):
  - one malformed JSON line is skipped + counted, never crashes the batch
  - missing user info is skipped + counted
  - an empty input yields an empty dict
"""

from __future__ import annotations

import json
import logging
from typing import Iterable, Iterator, Optional

logger = logging.getLogger(__name__)

# Kubernetes API verbs we recognize. An audit event whose verb is *not* in this
# set is still recorded (we surface what actually happened) but logged at info
# level so operators can spot non-standard verbs creeping in.
KNOWN_VERBS = frozenset(
    {
        "get",
        "list",
        "watch",
        "create",
        "update",
        "patch",
        "delete",
        "deletecollection",
        "proxy",
        "connect",
        "use",
        "bind",
        "escalate",
        "impersonate",
        "approve",
    }
)


def _iter_events(
    lines: Iterable[str],
) -> Iterator[tuple[Optional[dict], Optional[str]]]:
    """Yield ``(event_dict, warn_msg)`` per line.

    ``warn_msg`` is ``None`` when the line parsed cleanly, otherwise a short
    human-readable reason the line was skipped. Malformed JSON does not raise.
    """
    for raw in lines:
        if raw is None:
            continue
        line = raw.strip() if isinstance(raw, str) else raw
        if not line:
            continue  # blank lines are not warnings, just ignored
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, ValueError, TypeError):
            yield None, "malformed JSON line skipped"
            continue
        if not isinstance(event, dict):
            yield None, "non-object audit line skipped"
            continue
        yield event, None


def parse_audit_usage(lines: Iterable[str]) -> dict[str, set[tuple]]:
    """
    Parse Kubernetes apiserver audit JSON-lines into per-subject usage sets.

    Args:
        lines: iterable of raw audit-log lines (strings). No file I/O is done
            here — pass an open file object or a list of strings.

    Returns:
        ``{subject_key: {(verb, resource, namespace), ...}}``.

    Resilience: malformed lines and lines missing user info are skipped and
    counted via ``logger.warning``; a single bad line never aborts the batch
    and never raises.
    """
    usage: dict[str, set[tuple]] = {}
    skipped = 0

    for event, warn in _iter_events(lines):
        if event is None:
            skipped += 1
            logger.warning("[audit_ingest] %s (total skipped so far: %d)", warn, skipped)
            continue

        # Subject: the Kubernetes identity that performed the action.
        user = event.get("user")
        if not isinstance(user, dict):
            skipped += 1
            logger.warning(
                "[audit_ingest] missing user info skipped (total skipped so far: %d)",
                skipped,
            )
            continue
        subject_key = user.get("username")
        if not subject_key or not isinstance(subject_key, str):
            skipped += 1
            logger.warning(
                "[audit_ingest] missing user.username skipped (total skipped so far: %d)",
                skipped,
            )
            continue

        # Verb.
        verb = event.get("verb")
        if not isinstance(verb, str) or not verb:
            # A valid event with no verb is unusable for usage tracking.
            skipped += 1
            logger.warning(
                "[audit_ingest] missing verb skipped (total skipped so far: %d)",
                skipped,
            )
            continue
        if verb not in KNOWN_VERBS:
            logger.info("[audit_ingest] non-standard verb observed: %r", verb)

        # Resource + namespace from objectRef (non-resource requests have none).
        object_ref = event.get("objectRef") or {}
        if not isinstance(object_ref, dict):
            object_ref = {}
        resource = object_ref.get("resource")
        namespace = object_ref.get("namespace") or ""
        if resource is None:
            # Non-resource URL request (e.g. /healthz) — nothing to diff
            # against granted RBAC, so we don't record it as usage.
            continue

        usage.setdefault(subject_key, set()).add((verb, resource, namespace))

    if skipped:
        logger.warning(
            "[audit_ingest] finished with %d skipped line(s) (see above)", skipped
        )
    return usage
