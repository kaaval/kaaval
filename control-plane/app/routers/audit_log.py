"""
Audit log router — EE-only feature.

Provides a queryable, filterable view of all privileged actions recorded in the
audit_logs table. Results are read-only (append-only table).
"""

import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog
from ..auth import get_current_active_user
from ..license import license_gate

router = APIRouter(prefix="/audit", tags=["audit"])

_EE_DEP = [Depends(license_gate.require("audit_log"))]


class AuditLogEntry(BaseModel):
    id: uuid.UUID
    actor: str
    actor_ip: Optional[str]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    outcome: str
    detail: Optional[dict]
    created_at: datetime

    class Config:
        orm_mode = True


@router.get("", response_model=List[AuditLogEntry], dependencies=_EE_DEP)
def list_audit_logs(
    actor: Optional[str] = Query(None, description="Filter by actor username"),
    action: Optional[str] = Query(None, description="Exact action name or prefix (e.g. 'jit.')"),
    outcome: Optional[str] = Query(None, description="success | failure"),
    resource_type: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None, description="ISO8601 start timestamp"),
    until: Optional[datetime] = Query(None, description="ISO8601 end timestamp"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """
    List audit log entries for this tenant.
    Supports filtering by actor, action prefix, outcome, resource type, and time range.
    """
    q = db.query(AuditLog).filter(AuditLog.tenant_id == current_user.tenant_id)

    if actor:
        q = q.filter(AuditLog.actor == actor)
    if action:
        # Support prefix match: "jit." matches jit.approve, jit.deny, etc.
        if action.endswith("."):
            q = q.filter(AuditLog.action.like(f"{action}%"))
        else:
            q = q.filter(AuditLog.action == action)
    if outcome:
        q = q.filter(AuditLog.outcome == outcome)
    if resource_type:
        q = q.filter(AuditLog.resource_type == resource_type)
    if since:
        q = q.filter(AuditLog.created_at >= since)
    if until:
        q = q.filter(AuditLog.created_at <= until)

    return (
        q.order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/stats", dependencies=_EE_DEP)
def audit_stats(
    since: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """Return aggregate counts grouped by action and outcome."""
    from sqlalchemy import func

    q = db.query(
        AuditLog.action,
        AuditLog.outcome,
        func.count(AuditLog.id).label("count"),
    ).filter(AuditLog.tenant_id == current_user.tenant_id)

    if since:
        q = q.filter(AuditLog.created_at >= since)

    rows = q.group_by(AuditLog.action, AuditLog.outcome).all()
    result: dict = {}
    for action, outcome, count in rows:
        result.setdefault(action, {})
        result[action][outcome] = count
    return result
