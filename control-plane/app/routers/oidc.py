"""
Generic OIDC / SSO router — EE-only feature.

Supports any standards-compliant OIDC provider (Okta, Azure AD, Google Workspace,
Keycloak, etc.) via the discovery document at <issuer_url>/.well-known/openid-configuration.

Flow:
  1. Admin configures OIDC via POST /auth/oidc/configure
  2. User visits GET  /auth/oidc/login      → redirected to IdP
  3. IdP redirects to GET  /auth/oidc/callback  → JWT issued, redirect to frontend
"""

import uuid
import secrets
import logging
from datetime import datetime
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import OIDCConfig, User, Tenant
from ..auth import get_current_active_user, create_access_token, create_refresh_token, get_password_hash
from ..license import license_gate
import os

router = APIRouter(prefix="/auth/oidc", tags=["sso"])
logger = logging.getLogger(__name__)

_EE_DEP = [Depends(license_gate.require("sso"))]

# In-memory PKCE state store (replace with Redis/DB for multi-replica)
_state_store: dict[str, dict] = {}

FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")


# ── Schemas ───────────────────────────────────────────────────────────────────

class OIDCConfigCreate(BaseModel):
    provider_name: str
    issuer_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: str = "openid email profile"
    attribute_mapping: Optional[dict] = None


class OIDCConfigResponse(BaseModel):
    id: uuid.UUID
    provider_name: str
    issuer_url: str
    client_id: str
    redirect_uri: str
    scopes: str
    enabled: bool
    created_at: datetime

    class Config:
        orm_mode = True


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_discovery(issuer_url: str) -> dict:
    """Fetch the OIDC discovery document."""
    url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as http:
        res = await http.get(url)
    if res.status_code != 200:
        raise HTTPException(status_code=502, detail=f"OIDC discovery failed for {url}: {res.status_code}")
    return res.json()


def _get_tenant_oidc_config(db: Session) -> OIDCConfig:
    """Return the active OIDC config for the default tenant. Raise 404 if not configured."""
    default_tenant = uuid.UUID("00000000-0000-0000-0000-000000000000")
    cfg = db.query(OIDCConfig).filter(
        OIDCConfig.tenant_id == default_tenant,
        OIDCConfig.enabled == True,
    ).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="OIDC not configured. POST /auth/oidc/configure first.")
    return cfg


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/configure", response_model=OIDCConfigResponse, dependencies=_EE_DEP)
async def configure_oidc(
    body: OIDCConfigCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """Configure (or replace) the OIDC provider for this tenant. Admin only."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    # Verify the discovery document is reachable before saving
    await _get_discovery(body.issuer_url)

    existing = db.query(OIDCConfig).filter(
        OIDCConfig.tenant_id == current_user.tenant_id
    ).first()

    if existing:
        existing.provider_name = body.provider_name
        existing.issuer_url = body.issuer_url.rstrip("/")
        existing.client_id = body.client_id
        existing.client_secret = body.client_secret
        existing.redirect_uri = body.redirect_uri
        existing.scopes = body.scopes
        existing.attribute_mapping = body.attribute_mapping
        existing.enabled = True
        existing.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        return existing

    cfg = OIDCConfig(
        id=uuid.uuid4(),
        tenant_id=current_user.tenant_id,
        provider_name=body.provider_name,
        issuer_url=body.issuer_url.rstrip("/"),
        client_id=body.client_id,
        client_secret=body.client_secret,
        redirect_uri=body.redirect_uri,
        scopes=body.scopes,
        attribute_mapping=body.attribute_mapping,
    )
    db.add(cfg)
    db.commit()
    db.refresh(cfg)
    return cfg


@router.get("/configure", response_model=OIDCConfigResponse, dependencies=_EE_DEP)
def get_oidc_config(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    cfg = db.query(OIDCConfig).filter(
        OIDCConfig.tenant_id == current_user.tenant_id,
    ).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="OIDC not configured")
    return cfg


@router.get("/login")
async def oidc_login(db: Session = Depends(get_db)):
    """Redirect the browser to the IdP authorization endpoint."""
    cfg = _get_tenant_oidc_config(db)
    discovery = await _get_discovery(cfg.issuer_url)
    auth_endpoint = discovery["authorization_endpoint"]

    state = secrets.token_urlsafe(32)
    _state_store[state] = {"tenant_id": str(cfg.tenant_id), "created_at": datetime.utcnow().isoformat()}

    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "scope": cfg.scopes,
        "state": state,
    }
    query_string = "&".join(f"{k}={v}" for k, v in params.items())
    return RedirectResponse(f"{auth_endpoint}?{query_string}")


@router.get("/callback")
async def oidc_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: Session = Depends(get_db),
):
    """Handle the IdP redirect, exchange code for tokens, and issue a Provenance JWT."""
    if state not in _state_store:
        raise HTTPException(status_code=400, detail="Invalid or expired OIDC state")
    _state_store.pop(state)

    cfg = _get_tenant_oidc_config(db)
    discovery = await _get_discovery(cfg.issuer_url)
    token_endpoint = discovery["token_endpoint"]
    userinfo_endpoint = discovery.get("userinfo_endpoint")

    # Exchange code for tokens
    async with httpx.AsyncClient(timeout=15) as http:
        token_res = await http.post(token_endpoint, data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": cfg.redirect_uri,
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret,
        })

    if token_res.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Token exchange failed: {token_res.text}")

    token_data = token_res.json()
    idp_access_token = token_data.get("access_token")

    # Fetch user info
    user_email = None
    user_name = None
    if userinfo_endpoint and idp_access_token:
        async with httpx.AsyncClient(timeout=10) as http:
            ui_res = await http.get(userinfo_endpoint, headers={"Authorization": f"Bearer {idp_access_token}"})
        if ui_res.status_code == 200:
            info = ui_res.json()
            mapping = cfg.attribute_mapping or {}
            email_field = mapping.get("email", "email")
            name_field = mapping.get("name", "name")
            user_email = info.get(email_field) or info.get("email")
            user_name = info.get(name_field) or info.get("name") or user_email

    if not user_email:
        raise HTTPException(status_code=400, detail="Could not retrieve email from OIDC provider")

    # Provision user if new
    user = db.query(User).filter(User.username == user_email).first()
    if not user:
        pwd = secrets.token_urlsafe(24)
        user = User(
            id=uuid.uuid4(),
            tenant_id=cfg.tenant_id,
            username=user_email,
            password_hash=get_password_hash(pwd),
            role="viewer",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info(f"Provisioned new user via OIDC: {user_email}")

    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})

    return RedirectResponse(
        f"{FRONTEND_URL}/login?token={access_token}&refresh_token={refresh_token}&username={user.username}"
    )
