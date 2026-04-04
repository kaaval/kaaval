from fastapi import APIRouter, Depends
from .. import compliance
from ..auth import get_current_active_user

router = APIRouter(
    prefix="/compliance",
    tags=["compliance"],
    dependencies=[Depends(get_current_active_user)]
)

from sqlalchemy.orm import Session
from .. import database

@router.get("/dashboard")
def get_compliance_dashboard(db: Session = Depends(database.get_db)):
    return compliance.run_compliance_scan(db)

@router.get("/controls")
def get_security_controls(db: Session = Depends(database.get_db)):
    results = compliance.run_compliance_scan(db)
    return results["all_checks"]
