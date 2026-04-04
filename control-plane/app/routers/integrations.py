"""
Integration Hub — manages plugin configs, pull scheduling, push receivers,
and the compliance framework library (YAML rule packs).
"""
import glob
import hashlib
import hmac
import os
import uuid
import yaml
from datetime import datetime
from typing import List, Optional, Literal

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request, BackgroundTasks
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session

from .. import models, database, auth

router = APIRouter(
    prefix="/api/v1/integrations",
    tags=["integrations"],
    dependencies=[Depends(auth.get_current_active_user)],
)

PLUGINS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../plugins"))
EXTENSIONS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../extensions"))

# ── Plugin registry (loaded from plugins/<name>/plugin.yaml) ──────────────────

def _load_plugins() -> dict:
    plugins = {}
    for path in glob.glob(os.path.join(PLUGINS_DIR, "*/plugin.yaml")):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            plugin_id = data.get("meta", {}).get("id")
            if plugin_id:
                plugins[plugin_id] = data
        except Exception as e:
            print(f"Warning: failed to load plugin {path}: {e}")
    return plugins


_PLUGINS = _load_plugins()


@router.get("/plugins")
def list_plugins():
    """List all available integration plugins."""
    return [
        {
            "id": v["meta"]["id"],
            "name": v["meta"]["name"],
            "category": v["meta"].get("category", "other"),
            "description": v["meta"].get("description", ""),
            "connector_type": v.get("connector", {}).get("type", "pull"),
            "auth_schema": v.get("connector", {}).get("auth_schema", {}),
        }
        for v in _PLUGINS.values()
    ]


# ── Installed integrations ─────────────────────────────────────────────────────

class IntegrationInstall(BaseModel):
    plugin_id: str
    name: str
    config: dict = {}


class IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None
    config: Optional[dict] = None


@router.post("/install")
def install_integration(
    body: IntegrationInstall,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    plugin = _PLUGINS.get(body.plugin_id)
    if not plugin:
        raise HTTPException(status_code=404, detail=f"Plugin '{body.plugin_id}' not found")

    connector_type = plugin.get("connector", {}).get("type", "pull")
    integration = models.IntegrationConfig(
        id=uuid.uuid4(),
        tenant_id=current_user.tenant_id,
        plugin_id=body.plugin_id,
        name=body.name,
        enabled=True,
        config=body.config,
        connector_type=connector_type,
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return {"id": str(integration.id), "message": f"Integration '{body.name}' installed"}


@router.get("/installed")
def list_installed(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    integrations = db.query(models.IntegrationConfig).filter(
        models.IntegrationConfig.tenant_id == current_user.tenant_id
    ).all()
    return [
        {
            "id": str(i.id),
            "plugin_id": i.plugin_id,
            "name": i.name,
            "enabled": i.enabled,
            "connector_type": i.connector_type,
            "last_synced_at": i.last_synced_at,
            "created_at": i.created_at,
        }
        for i in integrations
    ]


@router.patch("/{integration_id}")
def update_integration(
    integration_id: uuid.UUID,
    body: IntegrationUpdate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    integration = db.query(models.IntegrationConfig).filter(
        models.IntegrationConfig.id == integration_id,
        models.IntegrationConfig.tenant_id == current_user.tenant_id,
    ).first()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    if body.name is not None:
        integration.name = body.name
    if body.enabled is not None:
        integration.enabled = body.enabled
    if body.config is not None:
        integration.config = body.config
    db.commit()
    return {"message": "Updated"}


@router.delete("/{integration_id}")
def uninstall_integration(
    integration_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    integration = db.query(models.IntegrationConfig).filter(
        models.IntegrationConfig.id == integration_id,
        models.IntegrationConfig.tenant_id == current_user.tenant_id,
    ).first()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    db.delete(integration)
    db.commit()
    return {"message": "Uninstalled"}


# ── Findings ───────────────────────────────────────────────────────────────────

@router.get("/{integration_id}/findings")
def list_findings(
    integration_id: uuid.UUID,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    query = db.query(models.IntegrationFinding).filter(
        models.IntegrationFinding.integration_id == integration_id,
        models.IntegrationFinding.tenant_id == current_user.tenant_id,
    )
    if severity:
        query = query.filter(models.IntegrationFinding.severity == severity.upper())
    if status:
        query = query.filter(models.IntegrationFinding.status == status)
    total = query.count()
    findings = query.order_by(models.IntegrationFinding.detected_at.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "findings": [
            {
                "id": str(f.id),
                "source_tool": f.source_tool,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "asset_id": f.asset_id,
                "cve_id": f.cve_id,
                "detected_at": f.detected_at,
                "status": f.status,
            }
            for f in findings
        ],
    }


# ── Push webhook receiver ─────────────────────────────────────────────────────

async def _verify_hmac(request: Request, secret: str) -> bytes:
    body = await request.body()
    sig = request.headers.get("X-Argus-Signature", "")
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, f"sha256={expected}"):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    return body


@router.post("/webhook/{integration_id}", dependencies=[])
async def push_webhook(
    integration_id: uuid.UUID,
    request: Request,
    db: Session = Depends(database.get_db),
):
    """Receive push events from integrations (syslog forwarder, alerting webhooks)."""
    integration = db.query(models.IntegrationConfig).filter(
        models.IntegrationConfig.id == integration_id,
    ).first()
    if not integration or not integration.enabled:
        raise HTTPException(status_code=404, detail="Integration not found or disabled")

    webhook_secret = integration.config.get("webhook_secret", "")
    body = await request.body()
    if webhook_secret:
        sig = request.headers.get("X-Argus-Signature", "")
        expected = "sha256=" + hmac.new(webhook_secret.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        import json
        payload = json.loads(body)
    except Exception:
        payload = {"raw": body.decode(errors="replace")}

    plugin = _PLUGINS.get(integration.plugin_id, {})
    norm = plugin.get("normalization", {})

    finding = models.IntegrationFinding(
        id=uuid.uuid4(),
        tenant_id=integration.tenant_id,
        integration_id=integration.id,
        source_tool=integration.plugin_id,
        finding_type=_extract(payload, norm.get("finding_type"), "log_event"),
        severity=_extract(payload, norm.get("severity"), "INFO").upper(),
        title=_extract(payload, norm.get("title"), f"Event from {integration.plugin_id}"),
        description=_extract(payload, norm.get("description"), ""),
        raw_payload=payload,
        asset_id=_extract(payload, norm.get("asset_id"), None),
        cve_id=_extract(payload, norm.get("cve_id"), None),
        detected_at=datetime.utcnow(),
    )
    db.add(finding)
    db.commit()
    return {"status": "accepted"}


def _extract(payload: dict, field_path: Optional[str], default):
    """Extract a value from a nested dict using dot notation."""
    if not field_path:
        return default
    parts = field_path.split(".")
    val = payload
    for p in parts:
        if not isinstance(val, dict):
            return default
        val = val.get(p, default)
    return val if val is not None else default


# ── Compliance rule packs (YAML upload) ───────────────────────────────────────

EXTENSIONS_DIR_INTEGRATIONS = os.path.join(EXTENSIONS_DIR, "integrations")


def _load_frameworks() -> List[dict]:
    frameworks = []
    os.makedirs(EXTENSIONS_DIR_INTEGRATIONS, exist_ok=True)
    for path in glob.glob(os.path.join(EXTENSIONS_DIR_INTEGRATIONS, "*.yaml")):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            if "meta" in data:
                frameworks.append(data["meta"])
        except Exception as e:
            print(f"Warning: failed to load framework {path}: {e}")
    return frameworks


class RuleCondition(BaseModel):
    operator: Literal["contains", "not_contains", "equals", "not_equals", "regex", "list_contains", "list_none_match"]
    field: str
    value: Optional[str] = None
    negate: bool = False

    class Config:
        extra = "forbid"


class IntegrationRule(BaseModel):
    id: str
    name: str
    description: Optional[str] = ""
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    target_asset_type: Literal["EC2", "IAM_USER", "S3_BUCKET", "EKS_CLUSTER", "VPC"]
    condition: RuleCondition
    remediation: Optional[str] = None

    class Config:
        extra = "forbid"


class IntegrationMeta(BaseModel):
    id: str = Field(..., pattern=r"^[a-zA-Z0-9\-_]+$")
    name: str
    version: str
    description: str
    price_tier: str = "Free"
    is_premium: bool = False

    class Config:
        extra = "forbid"


class IntegrationPackage(BaseModel):
    meta: IntegrationMeta
    checks: List[IntegrationRule]

    class Config:
        extra = "forbid"


@router.get("/frameworks/available")
def list_available_frameworks(db: Session = Depends(database.get_db)):
    return db.query(models.ComplianceFramework).all()


@router.post("/frameworks/upload")
async def upload_framework(
    file: UploadFile = File(...),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    content = await file.read()
    if len(content) > 1 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (max 1MB)")
    try:
        data = yaml.safe_load(content)
        if not data:
            raise HTTPException(status_code=400, detail="Empty YAML file")
        pkg = IntegrationPackage(**data)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")
    except ValidationError as e:
        errs = [f"{'.'.join(str(x) for x in err['loc'])}: {err['msg']}" for err in e.errors()]
        raise HTTPException(status_code=400, detail=f"Schema validation failed: {'; '.join(errs[:3])}")

    os.makedirs(EXTENSIONS_DIR_INTEGRATIONS, exist_ok=True)
    with open(os.path.join(EXTENSIONS_DIR_INTEGRATIONS, f"{pkg.meta.id}.yaml"), "wb") as f:
        f.write(content)

    existing = db.query(models.ComplianceFramework).filter_by(id=pkg.meta.id).first()
    if existing:
        existing.version = pkg.meta.version
        existing.description = pkg.meta.description
    else:
        db.add(models.ComplianceFramework(
            id=pkg.meta.id, name=pkg.meta.name, description=pkg.meta.description,
            version=pkg.meta.version, is_premium=pkg.meta.is_premium, price_tier=pkg.meta.price_tier,
        ))
    db.commit()
    return {"message": f"Framework '{pkg.meta.name}' uploaded", "id": pkg.meta.id}
