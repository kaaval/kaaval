from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict, Any, Optional
from ..k8s_client import k8s_client
from ..auth import get_current_active_user
from ..models import User

router = APIRouter(
    prefix="/k8s",
    tags=["kubernetes"],
    dependencies=[Depends(get_current_active_user)]
)

@router.get("/nodes")
def get_nodes():
    return k8s_client.get_nodes()

@router.get("/namespaces")
def get_namespaces():
    return k8s_client.get_namespaces()

@router.get("/pods/{namespace}")
def get_pods(namespace: str):
    return k8s_client.get_pods(namespace)

@router.get("/logs/{namespace}/{pod_name}")
def get_pod_logs(namespace: str, pod_name: str, tail: int = 100):
    return {"logs": k8s_client.get_logs(namespace, pod_name, tail)}

@router.get("/crds")
def get_crds():
    return k8s_client.get_crds()

@router.get("/status")
def get_k8s_status():
    return {"authorized": k8s_client.authorized}
