import os
import uuid
import secrets
import subprocess
from datetime import datetime, timedelta
from typing import List, Optional

import httpx
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import models, database, auth, audit
from .license import license_gate
from .cve_service import cve_service as _cve_service
from .routers import (
    compliance,
    integrations,
    dashboards,
    vulnerabilities,
    cve,
    rbac,
    siem,
    audit_log,
    clusters,
    oidc,
    attestation,
    jit,
    admin,
)

# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(title="Argus Control Plane", version="1.0.0")

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS", f"{FRONTEND_URL},http://localhost:3001"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ────────────────────────────────────────────────────────────────────

app.include_router(compliance.router)
app.include_router(integrations.router)
app.include_router(dashboards.router)
app.include_router(vulnerabilities.router)
app.include_router(cve.router)
app.include_router(rbac.router)
app.include_router(siem.router)
app.include_router(audit_log.router)
app.include_router(clusters.router)
app.include_router(oidc.router)
app.include_router(attestation.router)
app.include_router(jit.router)
app.include_router(admin.router)

# ── Default CVE feeds ──────────────────────────────────────────────────────────

DEFAULT_CVE_FEEDS = [
    {
        "name": "Kubernetes Official CVE Feed",
        "url": "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json",
        "feed_type": "json_feed",
        "description": "Official Kubernetes security CVE feed — updated by the Kubernetes security team",
    },
    {
        "name": "NVD — Kubernetes CVEs",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=kubernetes&resultsPerPage=2000",
        "feed_type": "nvd",
        "description": "NIST NVD filtered for Kubernetes vulnerabilities (includes CVSS scores)",
    },
    {
        "name": "NVD — containerd CVEs",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=containerd&resultsPerPage=500",
        "feed_type": "nvd",
        "description": "NIST NVD filtered for containerd runtime vulnerabilities",
    },
]

# ── Scheduler ──────────────────────────────────────────────────────────────────

from apscheduler.schedulers.asyncio import AsyncIOScheduler

_scheduler = AsyncIOScheduler()


async def _scheduled_cve_refresh():
    import logging
    logger = logging.getLogger(__name__)
    logger.info("Scheduled CVE feed refresh started")
    db = database.SessionLocal()
    try:
        results = await _cve_service.refresh_all_feeds(db)
        total = sum(r.get("entries_loaded", 0) for r in results if "entries_loaded" in r)
        logger.info(f"CVE refresh complete: {total} entries across {len(results)} feeds")
    except Exception as e:
        logger.error(f"CVE refresh failed: {e}")
    finally:
        db.close()


@app.on_event("startup")
async def startup_event():
    models.Base.metadata.create_all(bind=database.engine)

    db = database.SessionLocal()
    try:
        # Seed default tenant
        default_tenant_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        tenant = db.query(models.Tenant).filter(models.Tenant.id == default_tenant_id).first()
        if not tenant:
            db.add(models.Tenant(id=default_tenant_id, name="Default"))
            db.commit()

        # Seed default CVE feeds
        for feed_data in DEFAULT_CVE_FEEDS:
            if not db.query(models.CVEFeed).filter(models.CVEFeed.name == feed_data["name"]).first():
                db.add(models.CVEFeed(**feed_data))
        db.commit()
    finally:
        db.close()

    _scheduler.add_job(
        _scheduled_cve_refresh,
        trigger="interval",
        hours=24,
        id="refresh_cve_feeds",
        replace_existing=True,
    )

    from .routers.siem import forward_pending_audit_events
    _scheduler.add_job(
        forward_pending_audit_events,
        trigger="interval",
        seconds=30,
        id="siem_forward",
        replace_existing=True,
    )

    _scheduler.start()


@app.on_event("shutdown")
async def shutdown_event():
    _scheduler.shutdown(wait=False)


# ── Health / License ───────────────────────────────────────────────────────────

@app.get("/")
def health_check():
    return {"status": "ok", "service": "Argus Control Plane", "version": "1.0.0"}


@app.get("/license/status")
def license_status(current_user=Depends(auth.get_current_active_user)):
    return license_gate.status()


# ── Auth ───────────────────────────────────────────────────────────────────────

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/auth/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.password_hash):
        audit.audit_logger.log(
            action="auth.login_failure", actor=form_data.username,
            resource="auth", status="failure",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(data={"sub": user.username})
    refresh_token = auth.create_refresh_token(data={"sub": user.username})
    audit.audit_logger.log(
        action="auth.login_success", actor=user.username,
        resource="auth", status="success", tenant_id=str(user.tenant_id),
    )
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.post("/auth/refresh", response_model=Token)
async def refresh(body: RefreshRequest, db: Session = Depends(database.get_db)):
    username = auth.decode_refresh_token(body.refresh_token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {
        "access_token": auth.create_access_token(data={"sub": user.username}),
        "refresh_token": auth.create_refresh_token(data={"sub": user.username}),
        "token_type": "bearer",
    }


@app.post("/auth/seed")
def seed_admin(db: Session = Depends(database.get_db)):
    """First-run: create the admin user. Disabled after first call."""
    user = db.query(models.User).filter(models.User.username == "admin").first()
    if user:
        return {"message": "Admin already exists"}
    default_password = os.getenv("ARGUS_ADMIN_PASSWORD", secrets.token_urlsafe(12))
    tenant_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
    db.add(models.User(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        username="admin",
        password_hash=auth.get_password_hash(default_password),
        role="admin",
    ))
    db.commit()
    # Only print the password if we generated it (not from env)
    if not os.getenv("ARGUS_ADMIN_PASSWORD"):
        print(f"\n[Argus] Admin created — password: {default_password}\n")
        return {"message": "Admin created", "password": default_password}
    return {"message": "Admin created"}


# ── API Keys ───────────────────────────────────────────────────────────────────

class APIKeyCreate(BaseModel):
    name: str


class APIKeyResponse(BaseModel):
    name: str
    prefix: str
    key: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


@app.post("/auth/keys", response_model=APIKeyResponse)
def create_api_key(
    key_data: APIKeyCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    raw_key, prefix = auth.generate_api_key()
    db.add(models.APIKey(
        id=uuid.uuid4(),
        user_id=current_user.id,
        name=key_data.name,
        prefix=prefix,
        key_hash=auth.get_password_hash(raw_key),
    ))
    db.commit()
    audit.audit_logger.log(
        action="apikey.create", actor=current_user.username,
        resource="apikey", status="success",
        details={"name": key_data.name, "prefix": prefix},
        tenant_id=str(current_user.tenant_id),
    )
    return {"name": key_data.name, "prefix": prefix, "created_at": datetime.utcnow(), "key": raw_key}


@app.get("/auth/keys", response_model=List[APIKeyResponse])
def list_api_keys(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    return db.query(models.APIKey).filter(models.APIKey.user_id == current_user.id).all()


# ── Google OAuth ───────────────────────────────────────────────────────────────

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "mock")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "mock")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")


@app.get("/auth/google/login")
def login_google():
    if GOOGLE_CLIENT_ID == "mock":
        return RedirectResponse(f"{GOOGLE_REDIRECT_URI}?code=mock")
    scope = "openid email profile"
    return RedirectResponse(
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?response_type=code&client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}&scope={scope}&access_type=offline"
    )


@app.get("/auth/google/callback")
async def callback_google(code: str, db: Session = Depends(database.get_db)):
    if code == "mock":
        user_email = "mock_user@argus.dev"
    else:
        async with httpx.AsyncClient() as client:
            token_res = await client.post("https://oauth2.googleapis.com/token", data={
                "code": code, "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI, "grant_type": "authorization_code",
            })
            token_data = token_res.json()
            access_token = token_data.get("access_token")
            if not access_token:
                raise HTTPException(status_code=400, detail="Failed to get token from Google")
            user_info_res = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            user_email = user_info_res.json().get("email", "")

    if not user_email:
        raise HTTPException(status_code=400, detail="Email not found in provider response")

    user = db.query(models.User).filter(models.User.username == user_email).first()
    if not user:
        tenant_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        user = models.User(
            id=uuid.uuid4(), tenant_id=tenant_id, username=user_email,
            password_hash=auth.get_password_hash(secrets.token_urlsafe(16)),
            role="viewer",
        )
        db.add(user)
        db.commit()

    token = auth.create_access_token(data={"sub": user.username})
    return RedirectResponse(f"{FRONTEND_URL}/login?token={token}&username={user.username}")


# ── Tenants ────────────────────────────────────────────────────────────────────

class TenantCreate(BaseModel):
    name: str


class TenantSchema(BaseModel):
    id: uuid.UUID
    name: str
    created_at: datetime

    class Config:
        from_attributes = True


@app.post("/api/v1/tenants", response_model=TenantSchema)
def create_tenant(
    tenant: TenantCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    db_tenant = models.Tenant(id=uuid.uuid4(), name=tenant.name)
    db.add(db_tenant)
    db.commit()
    db.refresh(db_tenant)
    return db_tenant


# ── Cloud Accounts ─────────────────────────────────────────────────────────────

class AccountCreate(BaseModel):
    account_name: str
    account_id: str
    role_arn: str
    provider: str = "AWS"


@app.get("/api/v1/accounts")
def list_accounts(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    accounts = db.query(models.CloudAccount).filter(
        models.CloudAccount.tenant_id == current_user.tenant_id
    ).all()
    results = []
    for acc in accounts:
        count = db.query(models.Asset).filter(models.Asset.account_id == acc.account_id).count()
        regions = db.query(models.Asset.region).filter(
            models.Asset.account_id == acc.account_id
        ).distinct().all()
        results.append({
            "id": str(acc.id),
            "account_name": acc.account_name,
            "account_id": acc.account_id,
            "role_arn": acc.role_arn,
            "provider": acc.provider,
            "status": acc.status,
            "created_at": acc.created_at,
            "asset_count": count,
            "active_regions": [r[0] for r in regions if r[0]],
        })
    return results


@app.post("/api/v1/accounts")
def create_account(
    account: AccountCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    db.add(models.CloudAccount(
        tenant_id=current_user.tenant_id,
        account_name=account.account_name,
        account_id=account.account_id,
        role_arn=account.role_arn,
        provider=account.provider,
        status="active",
    ))
    db.commit()
    audit.audit_logger.log(
        action="account.onboard", actor=current_user.username,
        resource="account", status="success",
        details={"account_id": account.account_id, "provider": account.provider},
        tenant_id=str(current_user.tenant_id),
    )
    return {"message": "Account onboarded successfully"}


# ── Scans ──────────────────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    account_id: str
    region: str = "us-east-1"
    role_arn: Optional[str] = None
    all_regions: bool = False


class ScanSchema(BaseModel):
    id: uuid.UUID
    status: str
    started_at: Optional[datetime]
    region: Optional[str]

    class Config:
        from_attributes = True


@app.get("/api/v1/scans", response_model=List[ScanSchema])
def list_scans(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    return (
        db.query(models.Scan)
        .filter(models.Scan.tenant_id == current_user.tenant_id)
        .order_by(models.Scan.requested_at.desc())
        .limit(100)
        .all()
    )


@app.post("/api/v1/accounts/{account_id}/scan", response_model=ScanSchema)
def trigger_account_scan(
    account_id: str,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    account = db.query(models.CloudAccount).filter(
        models.CloudAccount.id == account_id,
        models.CloudAccount.tenant_id == current_user.tenant_id,
    ).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    scan_id = uuid.uuid4()
    db_scan = models.Scan(
        id=scan_id,
        tenant_id=current_user.tenant_id,
        account_id=account.account_id,
        status="PENDING",
        region="all",
        started_at=datetime.utcnow(),
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    # Dispatch scanner as a subprocess; pass scan ID via env
    scanner_bin = os.getenv("ARGUS_SCANNER_BIN", "./cloud-scanner/scanner")
    cmd = [scanner_bin]
    if account.role_arn:
        cmd.extend(["--role-arn", account.role_arn])
    cmd.append("--all-regions")

    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**os.environ, "ARGUS_SCAN_ID": str(scan_id), "DATABASE_URL": os.getenv("DATABASE_URL", "")},
        )
    except Exception as e:
        db_scan.status = "FAILED"
        db.commit()
        raise HTTPException(status_code=500, detail=f"Scanner launch failed: {e}")

    audit.audit_logger.log(
        action="scan.trigger", actor=current_user.username,
        resource="scan", status="initiated",
        details={"scan_id": str(scan_id), "account": account.account_id},
        tenant_id=str(current_user.tenant_id),
    )
    return db_scan


# ── Assets ─────────────────────────────────────────────────────────────────────

class AssetSchema(BaseModel):
    id: str
    asset_type: str
    region: str
    details: Optional[dict]

    class Config:
        from_attributes = True


@app.get("/api/v1/assets", response_model=List[AssetSchema])
def list_assets(
    scan_id: Optional[uuid.UUID] = None,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    query = db.query(models.Asset).filter(models.Asset.tenant_id == current_user.tenant_id)
    if scan_id:
        query = query.filter(models.Asset.scan_id == scan_id)
    return query.limit(500).all()


# ── Stats ──────────────────────────────────────────────────────────────────────

@app.get("/api/v1/stats")
def get_stats(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    tid = current_user.tenant_id
    total_assets = db.query(models.Asset).filter(models.Asset.tenant_id == tid).count()
    total_endpoints = db.query(models.Endpoint).filter(models.Endpoint.tenant_id == tid).count()
    online_endpoints = db.query(models.Endpoint).filter(
        models.Endpoint.tenant_id == tid, models.Endpoint.status == "ONLINE"
    ).count()
    open_findings = db.query(models.IntegrationFinding).filter(
        models.IntegrationFinding.tenant_id == tid,
        models.IntegrationFinding.status == "open",
    ).count()
    last_scan = (
        db.query(models.Scan)
        .filter(models.Scan.tenant_id == tid)
        .order_by(models.Scan.requested_at.desc())
        .first()
    )
    return {
        "total_assets": total_assets,
        "total_endpoints": total_endpoints,
        "online_endpoints": online_endpoints,
        "open_findings": open_findings,
        "last_scan": last_scan,
    }


# ── Agent enrollment / heartbeat ───────────────────────────────────────────────

class EndpointCreate(BaseModel):
    enrollment_token: str
    hostname: str
    os_info: str
    ip_address: Optional[str] = None


class EndpointHeartbeat(BaseModel):
    id: uuid.UUID
    enrollment_key: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_info: Optional[str] = None
    packages: Optional[list] = None  # [{name, version, arch}]


class EndpointSchema(BaseModel):
    id: uuid.UUID
    hostname: str
    ip_address: Optional[str]
    os_info: Optional[str]
    status: str
    last_seen: datetime

    class Config:
        from_attributes = True


@app.post("/api/v1/agents/enroll")
def enroll_agent(agent: EndpointCreate, db: Session = Depends(database.get_db)):
    try:
        tenant_id = uuid.UUID(agent.enrollment_token)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid enrollment token format")

    tenant = db.query(models.Tenant).filter(models.Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    enrollment_key = str(uuid.uuid4())
    new_endpoint = models.Endpoint(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        hostname=agent.hostname,
        os_info=agent.os_info,
        ip_address=agent.ip_address,
        status="ONLINE",
        enrollment_key=enrollment_key,
        last_seen=datetime.utcnow(),
    )
    db.add(new_endpoint)
    db.commit()
    db.refresh(new_endpoint)

    audit.audit_logger.log(
        action="agent.enroll", actor="agent", resource="endpoint", status="success",
        details={"hostname": agent.hostname, "ip": agent.ip_address},
        tenant_id=str(tenant_id),
    )
    return {"id": str(new_endpoint.id), "enrollment_key": enrollment_key, "message": "Enrolled successfully"}


@app.post("/api/v1/agents/heartbeat")
def agent_heartbeat(hb: EndpointHeartbeat, db: Session = Depends(database.get_db)):
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == hb.id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    if endpoint.enrollment_key != hb.enrollment_key:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    endpoint.last_seen = datetime.utcnow()
    endpoint.status = "ONLINE"
    if hb.hostname:
        endpoint.hostname = hb.hostname
    if hb.ip_address:
        endpoint.ip_address = hb.ip_address
    if hb.os_info:
        endpoint.os_info = hb.os_info
    if hb.packages is not None:
        endpoint.packages = hb.packages
    db.commit()
    return {"status": "ok"}


@app.get("/api/v1/endpoints", response_model=List[EndpointSchema])
def list_endpoints(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    return db.query(models.Endpoint).filter(
        models.Endpoint.tenant_id == current_user.tenant_id
    ).all()
