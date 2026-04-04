"""
Audit logging utility.

Usage in any router:
    from ..audit import audit

    audit(db, user, "jit.approve", resource_type="jit_request", resource_id=name)

For failure cases:
    audit(db, user, "jit.approve", outcome="failure", detail={"error": str(e)})
"""

import uuid
import logging
from typing import Optional, Any
from sqlalchemy.orm import Session
from .models import AuditLog

logger = logging.getLogger(__name__)

DEFAULT_TENANT = uuid.UUID("00000000-0000-0000-0000-000000000000")


def audit(
    db: Session,
    actor: Any,                         # User model instance or a username string
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    outcome: str = "success",
    detail: Optional[dict] = None,
    actor_ip: Optional[str] = None,
) -> None:
    """
    Write a single audit event to the database.
    Never raises — failures are logged but do not block the caller.
    """
    try:
        if hasattr(actor, "username"):
            tenant_id = actor.tenant_id
            actor_name = actor.username
        else:
            tenant_id = DEFAULT_TENANT
            actor_name = str(actor)

        entry = AuditLog(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            actor=actor_name,
            actor_ip=actor_ip,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            outcome=outcome,
            detail=detail,
        )
        db.add(entry)
        db.commit()
    except Exception as exc:
        logger.error(f"audit() failed to write event '{action}': {exc}")
