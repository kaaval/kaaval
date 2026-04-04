"""
Attestation router — EE-only feature.

Provides endpoints for managing cryptographic signing keys and verifying
signed provenance records attached to pods, images, or CI/CD workflow runs.

All endpoints require an active EE license with the "attestation" feature.
"""

import hashlib
import base64
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AttestationKey, AttestationRecord, Tenant
from ..auth import get_current_active_user
from ..license import license_gate

router = APIRouter(prefix="/attestation", tags=["attestation"])

_EE_DEP = [Depends(license_gate.require("attestation"))]


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class AttestationKeyCreate(BaseModel):
    name: str
    algorithm: str = "ES256"   # ES256 or RS256
    public_key_pem: str


class AttestationKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    algorithm: str
    fingerprint: str
    active: bool
    created_at: datetime
    rotated_at: Optional[datetime]

    class Config:
        orm_mode = True


class AttestationVerifyRequest(BaseModel):
    """Submit a signature to verify against a registered public key."""
    key_fingerprint: str
    subject: str          # pod name, image digest, etc.
    subject_type: str = "pod"
    payload_hash: str     # SHA-256 hex digest of the payload
    signature: str        # base64-encoded signature


class AttestationRecordResponse(BaseModel):
    id: uuid.UUID
    key_id: uuid.UUID
    subject: str
    subject_type: str
    payload_hash: str
    signed_at: datetime

    class Config:
        orm_mode = True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fingerprint(pem: str) -> str:
    """Return the SHA-256 fingerprint of a PEM-encoded public key."""
    raw = pem.strip().encode()
    return hashlib.sha256(raw).hexdigest()


def _verify_signature(algorithm: str, public_key_pem: str, payload_hash: str, signature_b64: str) -> bool:
    """Verify an ECDSA (ES256) or RSA (RS256) signature using the stored public key."""
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding
        from cryptography.exceptions import InvalidSignature

        pub_key = load_pem_public_key(public_key_pem.encode())
        sig_bytes = base64.b64decode(signature_b64)
        payload_bytes = bytes.fromhex(payload_hash)

        if algorithm == "ES256":
            pub_key.verify(sig_bytes, payload_bytes, ec.ECDSA(hashes.SHA256()))
        elif algorithm == "RS256":
            pub_key.verify(sig_bytes, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
        return True
    except (InvalidSignature, Exception):
        return False


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/keys", response_model=AttestationKeyResponse, dependencies=_EE_DEP)
def register_key(
    body: AttestationKeyCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """Register a new public signing key for attestation."""
    if body.algorithm not in ("ES256", "RS256"):
        raise HTTPException(status_code=422, detail="algorithm must be ES256 or RS256")

    fp = _fingerprint(body.public_key_pem)
    existing = db.query(AttestationKey).filter(AttestationKey.fingerprint == fp).first()
    if existing:
        raise HTTPException(status_code=409, detail="A key with this fingerprint is already registered")

    key = AttestationKey(
        id=uuid.uuid4(),
        tenant_id=current_user.tenant_id,
        name=body.name,
        algorithm=body.algorithm,
        public_key_pem=body.public_key_pem,
        fingerprint=fp,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return key


@router.get("/keys", response_model=List[AttestationKeyResponse], dependencies=_EE_DEP)
def list_keys(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    return db.query(AttestationKey).filter(
        AttestationKey.tenant_id == current_user.tenant_id
    ).order_by(AttestationKey.created_at.desc()).all()


@router.delete("/keys/{key_id}", status_code=204, dependencies=_EE_DEP)
def deactivate_key(
    key_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """Deactivate (soft-delete) a signing key. Does not remove existing records."""
    key = db.query(AttestationKey).filter(
        AttestationKey.id == key_id,
        AttestationKey.tenant_id == current_user.tenant_id,
    ).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    key.active = False
    key.rotated_at = datetime.utcnow()
    db.commit()


@router.post("/verify", response_model=AttestationRecordResponse, dependencies=_EE_DEP)
def verify_and_record(
    body: AttestationVerifyRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """
    Verify a signature against a registered key and persist the attestation record.
    Returns the stored record on success; 422 if the signature is invalid.
    """
    key = db.query(AttestationKey).filter(
        AttestationKey.fingerprint == body.key_fingerprint,
        AttestationKey.tenant_id == current_user.tenant_id,
        AttestationKey.active == True,
    ).first()
    if not key:
        raise HTTPException(status_code=404, detail="Active key with that fingerprint not found")

    if not _verify_signature(key.algorithm, key.public_key_pem, body.payload_hash, body.signature):
        raise HTTPException(status_code=422, detail="Signature verification failed")

    record = AttestationRecord(
        id=uuid.uuid4(),
        tenant_id=current_user.tenant_id,
        key_id=key.id,
        subject=body.subject,
        subject_type=body.subject_type,
        payload_hash=body.payload_hash,
        signature=body.signature,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.get("/records", response_model=List[AttestationRecordResponse], dependencies=_EE_DEP)
def list_records(
    subject: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    q = db.query(AttestationRecord).filter(
        AttestationRecord.tenant_id == current_user.tenant_id
    )
    if subject:
        q = q.filter(AttestationRecord.subject == subject)
    return q.order_by(AttestationRecord.signed_at.desc()).limit(500).all()
