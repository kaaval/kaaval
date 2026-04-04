from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
from .. import database, auth, models, audit
from ..vuln_ingest import query_osv

router = APIRouter(
    prefix="/api/v1/vulnerabilities",
    tags=["vulnerabilities"],
    dependencies=[Depends(auth.get_current_active_user)]
)

class Package(BaseModel):
    name: str
    version: str
    ecosystem: str = "PyPI"

class ScanRequest(BaseModel):
    packages: List[Package]
    asset_id: Optional[str] = None # Optional linking

class VulnerabilitySchema(BaseModel):
    id: str
    source: str
    severity: str
    description: Optional[str]
    published_at: Optional[datetime]
    
    class Config:
        from_attributes = True # Pydantic V2

@router.get("/", response_model=List[VulnerabilitySchema])
def list_vulnerabilities(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    return db.query(models.Vulnerability).offset(skip).limit(limit).all()

@router.post("/scan", response_model=List[VulnerabilitySchema])
async def scan_packages(request: ScanRequest, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    found_vulns = []
    
    # Process each package
    for pkg in request.packages:
        # Query OSV
        try:
            results = await query_osv(pkg.name, pkg.version, pkg.ecosystem)
        except Exception as e:
            print(f"Error querying OSV for {pkg.name}: {e}")
            continue
        
        for v in results:
             v_id = v.get("id")
             description = v.get("summary", "No description")
             
             # Upsert Definition
             db_vuln = db.query(models.Vulnerability).filter(models.Vulnerability.id == v_id).first()
             if not db_vuln:
                 # Try to parse published date
                 pub_date = datetime.utcnow()
                 if v.get("published"):
                     try:
                         # OSV format: 2022-01-01T00:00:00Z
                         pub_date = datetime.fromisoformat(v.get("published").replace("Z", "+00:00"))
                     except:
                         pass

                 db_vuln = models.Vulnerability(
                     id=v_id,
                     source="OSV",
                     severity="Medium", # Default for MVP
                     description=description,
                     published_at=pub_date
                 )
                 db.add(db_vuln)
                 db.commit()
                 db.refresh(db_vuln)
             
             # Avoid duplicates in return list
             if db_vuln.id not in [x.id for x in found_vulns]:
                 found_vulns.append(db_vuln)

    # Audit the Scan
    audit.audit_logger.log(
        action="vuln.scan",
        actor=current_user.username,
        resource="vulnerability",
        status="success",
        details={"packages_scanned": len(request.packages), "vulns_found": len(found_vulns)},
        tenant_id=str(current_user.tenant_id)
    )

    return found_vulns
