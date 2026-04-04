"""
Multi-cluster management router — EE-only feature.

Allows registering remote Kubernetes clusters via bearer token + API server URL.
Each cluster gets an on-demand K8s client scoped to that cluster's credentials.
"""

import uuid
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from kubernetes import client as k8s_client_lib
from kubernetes.client.rest import ApiException

from ..database import get_db
from ..models import ClusterRegistration
from ..auth import get_current_active_user
from ..license import license_gate

router = APIRouter(prefix="/clusters", tags=["clusters"])
logger = logging.getLogger(__name__)

_EE_DEP = [Depends(license_gate.require("multi_cluster"))]


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ClusterCreate(BaseModel):
    name: str
    api_server_url: str
    bearer_token: str
    ca_cert_pem: Optional[str] = None
    environment: str = "production"


class ClusterResponse(BaseModel):
    id: uuid.UUID
    name: str
    api_server_url: str
    environment: str
    active: bool
    last_seen: Optional[datetime]
    created_at: datetime

    class Config:
        orm_mode = True


class ClusterHealth(BaseModel):
    cluster_id: uuid.UUID
    name: str
    reachable: bool
    node_count: Optional[int]
    server_version: Optional[str]
    error: Optional[str]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_k8s_client(cluster: ClusterRegistration):
    """Build a CoreV1Api client scoped to the given cluster's credentials."""
    configuration = k8s_client_lib.Configuration()
    configuration.host = cluster.api_server_url
    configuration.api_key = {"authorization": f"Bearer {cluster.bearer_token}"}

    if cluster.ca_cert_pem:
        import tempfile, os
        ca_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        ca_file.write(cluster.ca_cert_pem.encode())
        ca_file.flush()
        configuration.ssl_ca_cert = ca_file.name
    else:
        configuration.verify_ssl = False  # dev/test only

    api_client = k8s_client_lib.ApiClient(configuration)
    return k8s_client_lib.CoreV1Api(api_client), k8s_client_lib.VersionApi(api_client)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("", response_model=ClusterResponse, dependencies=_EE_DEP)
def register_cluster(
    body: ClusterCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """Register a new remote cluster."""
    existing = db.query(ClusterRegistration).filter(
        ClusterRegistration.tenant_id == current_user.tenant_id,
        ClusterRegistration.name == body.name,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Cluster '{body.name}' is already registered")

    cluster = ClusterRegistration(
        id=uuid.uuid4(),
        tenant_id=current_user.tenant_id,
        name=body.name,
        api_server_url=body.api_server_url.rstrip("/"),
        bearer_token=body.bearer_token,
        ca_cert_pem=body.ca_cert_pem,
        environment=body.environment,
    )
    db.add(cluster)
    db.commit()
    db.refresh(cluster)
    return cluster


@router.get("", response_model=List[ClusterResponse], dependencies=_EE_DEP)
def list_clusters(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    return db.query(ClusterRegistration).filter(
        ClusterRegistration.tenant_id == current_user.tenant_id
    ).order_by(ClusterRegistration.created_at.desc()).all()


@router.delete("/{cluster_id}", status_code=204, dependencies=_EE_DEP)
def deregister_cluster(
    cluster_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    cluster = db.query(ClusterRegistration).filter(
        ClusterRegistration.id == cluster_id,
        ClusterRegistration.tenant_id == current_user.tenant_id,
    ).first()
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")
    cluster.active = False
    db.commit()


@router.get("/{cluster_id}/health", response_model=ClusterHealth, dependencies=_EE_DEP)
def cluster_health(
    cluster_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """Probe a registered cluster and return health information."""
    cluster = db.query(ClusterRegistration).filter(
        ClusterRegistration.id == cluster_id,
        ClusterRegistration.tenant_id == current_user.tenant_id,
        ClusterRegistration.active == True,
    ).first()
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    try:
        core_v1, version_api = _build_k8s_client(cluster)
        nodes = core_v1.list_node()
        server_version = version_api.get_code()
        cluster.last_seen = datetime.utcnow()
        db.commit()
        return ClusterHealth(
            cluster_id=cluster.id,
            name=cluster.name,
            reachable=True,
            node_count=len(nodes.items),
            server_version=f"{server_version.major}.{server_version.minor}",
        )
    except ApiException as e:
        return ClusterHealth(cluster_id=cluster.id, name=cluster.name, reachable=False, error=str(e))
    except Exception as e:
        return ClusterHealth(cluster_id=cluster.id, name=cluster.name, reachable=False, error=str(e))


@router.get("/{cluster_id}/nodes", dependencies=_EE_DEP)
def cluster_nodes(
    cluster_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    """List nodes of a registered remote cluster."""
    cluster = db.query(ClusterRegistration).filter(
        ClusterRegistration.id == cluster_id,
        ClusterRegistration.tenant_id == current_user.tenant_id,
        ClusterRegistration.active == True,
    ).first()
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    try:
        core_v1, _ = _build_k8s_client(cluster)
        nodes = core_v1.list_node()
        return [
            {
                "name": n.metadata.name,
                "status": n.status.conditions[-1].type if n.status.conditions else "Unknown",
                "version": n.status.node_info.kubelet_version,
                "roles": [
                    k.replace("node-role.kubernetes.io/", "")
                    for k in (n.metadata.labels or {})
                    if k.startswith("node-role.kubernetes.io/")
                ],
            }
            for n in nodes.items
        ]
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach cluster: {e}")


@router.get("/{cluster_id}/namespaces", dependencies=_EE_DEP)
def cluster_namespaces(
    cluster_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
):
    cluster = db.query(ClusterRegistration).filter(
        ClusterRegistration.id == cluster_id,
        ClusterRegistration.tenant_id == current_user.tenant_id,
        ClusterRegistration.active == True,
    ).first()
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    try:
        core_v1, _ = _build_k8s_client(cluster)
        ns_list = core_v1.list_namespace()
        return [n.metadata.name for n in ns_list.items]
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach cluster: {e}")
