"""
SIEM integration router — EE-only feature.

Supports three destination types:
  splunk_hec  — Splunk HTTP Event Collector
  elastic     — Elasticsearch /_doc endpoint
  webhook     — generic HTTP POST (e.g. custom SOAR, Datadog, Slack)

A background job (scheduled every 30 s in main.py) picks up new audit events
and forwards them to every enabled SIEM configuration.
"""

import uuid
import logging
from datetime import datetime
from typing import List, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db, SessionLocal
from ..models import SIEMConfig, AuditLog
from ..auth import get_current_active_user
from ..license import license_gate

router = APIRouter(prefix="/siem", tags=["siem"])
logger = logging.getLogger(__name__)

_EE_DEP = [Depends(license_gate.require("siem"))]

# ── Schemas ───────────────────────────────────────────────────────────────────

class SIEMConfigCreate(BaseModel):
    name: str
    siem_type: str = "webhook"   # splunk_hec | elastic | webhook
    endpoint_url: str
    api_key: Optional[str] = None
    filters: Optional[dict] = None


class SIEMConfigResponse(BaseModel):
    id: uuid.UUID
    name: str
    siem_type: str
    endpoint_url: str
    filters: Optional[dict]
    enabled: bool
    last_forwarded_at: Optional[datetime]
    created_at: datetime

    class Config:
        orm_mode = True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_headers(cfg: SIEMConfig) -> dict:
    if cfg.siem_type == "splunk_hec":
        return {"Authorization": f"Splunk {cfg.api_key}", "Content-Type": "application/json"}
    if cfg.siem_type == "elastic":
        return {"Authorization": f"ApiKey {cfg.api_key}", "Content-Type": "application/json"}
    # generic webhook
    if cfg.api_key:
        return {"Authorization": f"Bearer {cfg.api_key}", "Content-Type": "application/json"}
    return {"Content-Type": "application/json"}


def _audit_to_payload(cfg: SIEMConfig, entry: AuditLog) -> dict:
    """Convert an AuditLog row to the destination-specific payload."""
    event = {
        "id": str(entry.id),
        "tenant_id": str(entry.tenant_id),
        "actor": entry.actor,
        "actor_ip": entry.actor_ip,
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "outcome": entry.outcome,
        "detail": entry.detail,
        "timestamp": entry.created_at.isoformat() + "Z",
        "source": "provenance-k8s",
    }
    if cfg.siem_type == "splunk_hec":
        return {"time": entry.created_at.timestamp(), "event": event, "sourcetype": "provenance:audit"}
    # elastic and webhook: send the event dict directly
    return event


def _matches_filter(cfg: SIEMConfig, entry: AuditLog) -> bool:
    """Return True if the entry passes the SIEM config's filters."""
    f = cfg.filters or {}
    if "actions" in f and entry.action not in f["actions"]:
        return False
    if f.get("min_outcome") == "failure" and entry.outcome != "failure":
        return False
    return True


async def _forward_to_siem(cfg: SIEMConfig, entries: list[AuditLog]) -> int:
    """Forward a batch of audit events to a SIEM endpoint. Returns count forwarded."""
    headers = _build_headers(cfg)
    forwarded = 0
    async with httpx.AsyncClient(timeout=10) as client:
        for entry in entries:
            if not _matches_filter(cfg, entry):
                continue
            payload = _audit_to_payload(cfg, entry)
            try:
                res = await client.post(cfg.endpoint_url, json=payload, headers=headers)
                if res.status_code < 300:
                    forwarded += 1
                else:
                    logger.warning(f"SIEM {cfg.name}: HTTP {res.status_code} for event {entry.id}")
            except Exception as e:
                logger.warning(f"SIEM {cfg.name}: failed to send event {entry.id}: {e}")
    return forwarded


async def forward_pending_audit_events() -> None:
    """
    Background job — called by APScheduler every 30 s.
    For each enabled SIEM config, forward audit events recorded since last_forwarded_at.
    """
    db: Session = SessionLocal()
    try:
        configs = db.query(SIEMConfig).filter(SIEMConfig.enabled == True).all()
        for cfg in configs:
            q = db.query(AuditLog).filter(AuditLog.tenant_id == cfg.tenant_id)
            if cfg.last_forwarded_at:
                q = q.filter(AuditLog.created_at > cfg.last_forwarded_at)
            entries = q.order_by(AuditLog.created_at.asc()).limit(500).all()
            if not entries:
                continue
            forwarded = await _forward_to_siem(cfg, entries)
            if forwarded > 0 or entries:
                cfg.last_forwarded_at = entries[-1].created_at
                db.commit()
                logger.info(f"SIEM {cfg.name}: forwarded {forwarded}/{len(entries)} events")
    except Exception as e:
        logger.error(f"SIEM forward job failed: {e}")
    finally:
        db.close()


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("", response_model=SIEMConfigResponse, dependencies=_EE_DEP)
def create_siem_config(
    body: SIEMConfigCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    if body.siem_type not in ("splunk_hec", "elastic", "webhook"):
        raise HTTPException(status_code=422, detail="siem_type must be splunk_hec, elastic, or webhook")

    cfg = SIEMConfig(
        id=uuid.uuid4(),
        tenant_id=current_user.tenant_id,
        name=body.name,
        siem_type=body.siem_type,
        endpoint_url=body.endpoint_url,
        api_key=body.api_key,
        filters=body.filters,
    )
    db.add(cfg)
    db.commit()
    db.refresh(cfg)
    return cfg


@router.get("", response_model=List[SIEMConfigResponse], dependencies=_EE_DEP)
def list_siem_configs(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    return db.query(SIEMConfig).filter(
        SIEMConfig.tenant_id == current_user.tenant_id
    ).order_by(SIEMConfig.created_at.desc()).all()


@router.delete("/{config_id}", status_code=204, dependencies=_EE_DEP)
def delete_siem_config(
    config_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    cfg = db.query(SIEMConfig).filter(
        SIEMConfig.id == config_id,
        SIEMConfig.tenant_id == current_user.tenant_id,
    ).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="SIEM config not found")
    db.delete(cfg)
    db.commit()


@router.post("/{config_id}/test", dependencies=_EE_DEP)
async def test_siem_config(
    config_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """Send a test event to verify the SIEM endpoint is reachable."""
    cfg = db.query(SIEMConfig).filter(
        SIEMConfig.id == config_id,
        SIEMConfig.tenant_id == current_user.tenant_id,
    ).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="SIEM config not found")

    test_payload: dict = {
        "id": "test-event",
        "actor": current_user.username,
        "action": "siem.test",
        "outcome": "success",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source": "provenance-k8s",
        "message": "Provenance-K8s SIEM test event",
    }
    if cfg.siem_type == "splunk_hec":
        test_payload = {"time": datetime.utcnow().timestamp(), "event": test_payload, "sourcetype": "provenance:audit"}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.post(cfg.endpoint_url, json=test_payload, headers=_build_headers(cfg))
        return {"status": "ok" if res.status_code < 300 else "error", "http_status": res.status_code}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
