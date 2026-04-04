from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from .. import database, auth, models, audit

router = APIRouter(
    prefix="/api/v1/admin",
    tags=["admin"],
    dependencies=[Depends(auth.get_current_active_user)] # Basic Auth for now, refine to Admin Only later
)

class DBStatus(BaseModel):
    mode: str
    connection_url: str # Masked
    status: str

class SwitchRequest(BaseModel):
    mode: str

@router.get("/db-status", response_model=DBStatus)
def get_db_status():
    manager = database.db_manager
    current_mode = manager.mode
    
    # Check connection health (simple query)
    status_msg = "connected"
    try:
        # We need a temporary session to check connectivity
        session = manager.get_session()
        session.execute(database.text("SELECT 1"))
        session.close()
    except Exception as e:
        status_msg = f"error: {str(e)}"

    # Mask URL for security
    url = str(manager.engine.url)
    masked_url = url.split("@")[0] + "@***" if "@" in url else "***"

    return {
        "mode": current_mode,
        "connection_url": masked_url,
        "status": status_msg
    }

@router.post("/db-switch")
def switch_db_mode(request: SwitchRequest, current_user: models.User = Depends(auth.get_current_active_user)):
    # Verify Admin Role
    if current_user.role != "admin":
         # Audit Failure
         audit.audit_logger.log(
            action="db.switch_mode_attempt",
            actor=current_user.username,
            resource="database",
            status="failure",
            details={"mode": request.mode, "reason": "unauthorized"},
            tenant_id=str(current_user.tenant_id)
         )
         raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )

    try:
        database.db_manager.switch_mode(request.mode)
        
        # Audit Success
        audit.audit_logger.log(
            action="db.switch_mode",
            actor=current_user.username,
            resource="database",
            status="success",
            details={"mode": request.mode},
            tenant_id=str(current_user.tenant_id)
        )
        
        return {"message": f"Switched to {request.mode} mode successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to switch DB: {str(e)}")
