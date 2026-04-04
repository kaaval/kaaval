"""
JIT Access Request router — EE-only feature.

Approval workflow:
  Pending → (admin approves) → Approved → (operator creates RoleBinding) → Active → Expired
  Pending → (admin denies)  → Denied

The Operator watches JITAccessRequest CRDs:
  - On Approved: creates a time-bound RoleBinding and sets status.state = Active
  - On expiry:   removes the RoleBinding and sets status.state = Expired
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional, List
from ..k8s_client import k8s_client
from ..auth import get_current_active_user, User
from ..license import license_gate
from ..database import get_db
from ..audit import audit

router = APIRouter(
    prefix="/jit",
    tags=["jit"],
    dependencies=[Depends(get_current_active_user), Depends(license_gate.require("jit"))]
)

_ROLE_MAP = {
    "admin": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "admin"},
    "edit":  {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "edit"},
    "view":  {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"},
}

JIT_NAMESPACE = "default"       # central namespace where JITAccessRequest CRDs live
JIT_GROUP     = "provenance.io"
JIT_VERSION   = "v1alpha1"
JIT_PLURAL    = "jitaccessrequests"


class JITRequestCreate(BaseModel):
    namespace: str
    target_role: str    # admin | edit | view (or a custom ClusterRole name)
    duration: str       # e.g. "1h", "30m", "4h"
    reason: str


@router.get("/requests")
def list_requests(user: User = Depends(get_current_active_user)):
    """List all JIT requests in the management namespace."""
    res = k8s_client.list_jit_requests(JIT_NAMESPACE)
    if isinstance(res, list):
        return res
    return res.get("items", [])


@router.post("/request")
def create_request(req: JITRequestCreate, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    """Submit a new JIT access request. Initial state: Pending."""
    role_ref = _ROLE_MAP.get(req.target_role) or {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "ClusterRole",
        "name": req.target_role,
    }
    try:
        result = k8s_client.create_jit_request(
            namespace=JIT_NAMESPACE,
            requestor=user.username,
            role_ref=role_ref,
            duration=req.duration,
            reason=req.reason,
        )
        audit(db, user, "jit.request", resource_type="jit_request",
              detail={"namespace": req.namespace, "role": req.target_role, "duration": req.duration})
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/requests/{name}/approve")
def approve_request(name: str, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    """
    Approve a pending JIT request (admin only).
    Patches the CRD status to state=Approved; the Operator then creates the RoleBinding.
    """
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required to approve JIT requests")

    if not k8s_client.authorized:
        raise HTTPException(status_code=503, detail="Kubernetes API unavailable")

    patch = {
        "status": {
            "state": "Approved",
            "approvedBy": user.username,
        }
    }
    try:
        result = k8s_client.custom_objects.patch_namespaced_custom_object_status(
            JIT_GROUP, JIT_VERSION, JIT_NAMESPACE, JIT_PLURAL, name, patch
        )
        audit(db, user, "jit.approve", resource_type="jit_request", resource_id=name)
        return result
    except Exception as e:
        audit(db, user, "jit.approve", resource_type="jit_request", resource_id=name,
              outcome="failure", detail={"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/requests/{name}/deny")
def deny_request(name: str, reason: Optional[str] = None, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    """
    Deny a pending JIT request (admin only).
    Patches the CRD status to state=Denied.
    """
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required to deny JIT requests")

    if not k8s_client.authorized:
        raise HTTPException(status_code=503, detail="Kubernetes API unavailable")

    patch = {
        "status": {
            "state": "Denied",
            "deniedBy": user.username,
            "denialReason": reason or "Request denied by administrator",
        }
    }
    try:
        result = k8s_client.custom_objects.patch_namespaced_custom_object_status(
            JIT_GROUP, JIT_VERSION, JIT_NAMESPACE, JIT_PLURAL, name, patch
        )
        audit(db, user, "jit.deny", resource_type="jit_request", resource_id=name,
              detail={"reason": reason})
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/requests/{name}", status_code=204)
def delete_request(name: str, user: User = Depends(get_current_active_user)):
    """Delete (retract) a JIT request. Requestor can only delete their own; admins can delete any."""
    if not k8s_client.authorized:
        raise HTTPException(status_code=503, detail="Kubernetes API unavailable")

    try:
        # Fetch the CR to check ownership
        cr = k8s_client.custom_objects.get_namespaced_custom_object(
            JIT_GROUP, JIT_VERSION, JIT_NAMESPACE, JIT_PLURAL, name
        )
        requestor = cr.get("spec", {}).get("requestor")
        if user.role != "admin" and requestor != user.username:
            raise HTTPException(status_code=403, detail="You can only retract your own requests")

        k8s_client.custom_objects.delete_namespaced_custom_object(
            JIT_GROUP, JIT_VERSION, JIT_NAMESPACE, JIT_PLURAL, name
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
