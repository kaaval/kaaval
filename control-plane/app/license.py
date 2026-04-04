"""
License gate — controls access to Enterprise Edition features.

Community Edition (CE) features are always accessible.
Enterprise Edition (EE) features require a valid license token.

License token format: a signed JWT containing:
  {
    "customer": "Acme Corp",
    "features": ["compliance_advanced", "jit", "multi_cluster", "sso", "audit_log"],
    "clusters": 5,
    "exp": <unix timestamp>
  }

Usage:
    from .license import license_gate

    # FastAPI dependency
    @router.get("/ee-endpoint", dependencies=[Depends(license_gate.require("jit"))])

    # Programmatic check
    if license_gate.has("multi_cluster"):
        ...
"""

import os
import logging
from datetime import datetime
from typing import Optional
from functools import lru_cache

from fastapi import HTTPException

logger = logging.getLogger(__name__)

EE_FEATURES: dict[str, str] = {
    "compliance_advanced": "Advanced Compliance (CIS, SOC2, PCI report export)",
    "jit": "Just-In-Time Access Management",
    "multi_cluster": "Multi-Cluster Management",
    "sso": "SSO / OIDC / SAML Identity Federation",
    "audit_log": "Tamper-Evident Audit Logging",
    "drift_detection": "GitOps Drift Detection",
    "why_engine": "AI Why Engine (autonomous root-cause analysis)",
    "siem": "SIEM Integrations (Splunk, Datadog, Elastic)",
    "extended_retention": "Extended Data Retention & Tiered Storage",
    "attestation": "Cryptographic Provenance Attestation",
}

CE_FEATURES = {
    "cve_scan",
    "rbac_graph",
    "basic_compliance",
    "nl_query",
    "ebpf_collector",
    "k8s_dashboard",
    "cloud_cspm",
    "agent_enrollment",
    "integration_hub",
    "widget_dashboard",
}

_LICENSE_PUBLIC_KEY = os.getenv("ARGUS_LICENSE_PUBKEY", "")
_LICENSE_TOKEN_ENV = "ARGUS_LICENSE_TOKEN"


class LicenseInfo:
    def __init__(self, customer: str, features: list[str], clusters: int, expires: Optional[datetime], valid: bool):
        self.customer = customer
        self.features = set(features)
        self.clusters = clusters
        self.expires = expires
        self.valid = valid

    def is_expired(self) -> bool:
        return self.expires is not None and datetime.utcnow() > self.expires

    def has(self, feature: str) -> bool:
        if not self.valid or self.is_expired():
            return False
        return feature in self.features or "*" in self.features


_CE_LICENSE = LicenseInfo(
    customer="Community Edition",
    features=[],
    clusters=1,
    expires=None,
    valid=True,
)


@lru_cache(maxsize=1)
def _load_license() -> LicenseInfo:
    token = os.getenv(_LICENSE_TOKEN_ENV, "").strip()

    if not token:
        license_file = os.getenv("ARGUS_LICENSE_FILE", "/etc/argus/license.jwt")
        try:
            with open(license_file) as f:
                token = f.read().strip()
        except (FileNotFoundError, PermissionError):
            pass

    if not token:
        logger.info("No license token found — running as Community Edition")
        return _CE_LICENSE

    try:
        from jose import jwt, JWTError
        if not _LICENSE_PUBLIC_KEY:
            logger.warning("License token present but ARGUS_LICENSE_PUBKEY not set — skipping signature check (dev mode)")
            payload = jwt.decode(token, "dev-mode", algorithms=["HS256", "RS256", "ES256"], options={"verify_signature": False})
        else:
            payload = jwt.decode(token, _LICENSE_PUBLIC_KEY, algorithms=["RS256", "ES256"])

        exp_ts = payload.get("exp")
        expires = datetime.utcfromtimestamp(exp_ts) if exp_ts else None
        features = payload.get("features", [])
        clusters = payload.get("clusters", 1)
        customer = payload.get("customer", "Unknown")

        info = LicenseInfo(customer=customer, features=features, clusters=clusters, expires=expires, valid=True)
        if info.is_expired():
            logger.warning(f"License for '{customer}' expired on {expires}")
        else:
            logger.info(f"Enterprise license loaded for '{customer}' — features: {features}")
        return info

    except Exception as e:
        logger.error(f"License token validation failed: {e}")
        return _CE_LICENSE


class LicenseGate:
    @property
    def info(self) -> LicenseInfo:
        return _load_license()

    def has(self, feature: str) -> bool:
        return self.info.has(feature)

    def require(self, feature: str):
        def _check():
            if not self.has(feature):
                friendly = EE_FEATURES.get(feature, feature)
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "enterprise_feature_required",
                        "feature": feature,
                        "feature_name": friendly,
                        "message": (
                            f"'{friendly}' requires an Enterprise Edition license. "
                            "Set ARGUS_LICENSE_TOKEN to enable."
                        ),
                    },
                )
        return _check

    def status(self) -> dict:
        info = self.info
        return {
            "edition": "enterprise" if (info.valid and info.features) else "community",
            "customer": info.customer,
            "valid": info.valid,
            "expired": info.is_expired(),
            "expires": info.expires.isoformat() if info.expires else None,
            "max_clusters": info.clusters,
            "licensed_features": sorted(info.features),
            "available_ee_features": {k: v for k, v in EE_FEATURES.items()},
        }


license_gate = LicenseGate()
