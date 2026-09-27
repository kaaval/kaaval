"""Authenticated, bounded report ingestion using the tenant's stored context."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import get_current_active_user
from ..cve_service import cve_service
from ..database import get_db
from ..image_ingest import GrypeReport, TrivyReport, score_report
from ..models import IngestedScanResult
from ..request_limits import json_body_openapi, limited_json_body

router = APIRouter(prefix="/ingest", tags=["Image ingestion"])


def _response(scan: IngestedScanResult) -> dict:
    return {**scan.result, "id": str(scan.id), "scanned_at": scan.scanned_at.isoformat()}


def _store(report, db: Session, user) -> dict:
    context = cve_service._context_to_dict(
        cve_service.get_or_create_scan_context(db, user.tenant_id)
    )
    scan = IngestedScanResult(
        tenant_id=user.tenant_id,
        source="trivy" if isinstance(report, TrivyReport) else "grype",
        result=score_report(report, context),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return _response(scan)


@router.post("/trivy", status_code=201, openapi_extra=json_body_openapi(TrivyReport))
def ingest_trivy(
    user=Depends(get_current_active_user),
    body: TrivyReport = Depends(limited_json_body(TrivyReport)),
    db: Session = Depends(get_db),
):
    return _store(body, db, user)


@router.post("/grype", status_code=201, openapi_extra=json_body_openapi(GrypeReport))
def ingest_grype(
    user=Depends(get_current_active_user),
    body: GrypeReport = Depends(limited_json_body(GrypeReport)),
    db: Session = Depends(get_db),
):
    return _store(body, db, user)


@router.get("/scans/latest")
def latest_scan(
    source: Literal["trivy", "grype"] | None = None,
    user=Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    query = db.query(IngestedScanResult).filter(IngestedScanResult.tenant_id == user.tenant_id)
    if source:
        query = query.filter(IngestedScanResult.source == source)
    scan = query.order_by(IngestedScanResult.scanned_at.desc(), IngestedScanResult.id.desc()).first()
    if scan is None:
        raise HTTPException(404, "No imported image scan for this tenant. POST /ingest/trivy or /ingest/grype first.")
    return _response(scan)
