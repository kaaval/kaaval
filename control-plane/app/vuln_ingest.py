import httpx
from sqlalchemy.orm import Session
from . import models
from datetime import datetime
import logging

logger = logging.getLogger("vuln_ingest")
OSV_API_URL = "https://api.osv.dev/v1/query"

async def query_osv(package: str, version: str, ecosystem: str = "PyPI"):
    payload = {
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version
    }
    
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(OSV_API_URL, json=payload)
            if resp.status_code == 200:
                return resp.json().get("vulns", [])
            return []
        except Exception as e:
            logger.error(f"OSV Query Failed for {package}: {e}")
            return []

async def process_scan(asset_id: str, packages: list, db: Session):
    """
    Scans a list of packages and updates the database.
    packages: list of dicts {'name': 'x', 'version': 'y', 'ecosystem': 'z'}
    """
    found_vulns = []
    
    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")
        ecosystem = pkg.get("ecosystem", "PyPI") # Default
        
        vulns = await query_osv(name, version, ecosystem)
        
        for v in vulns:
            v_id = v.get("id")
            
            # 1. Upsert Vulnerability Definition
            db_vuln = db.query(models.Vulnerability).filter(models.Vulnerability.id == v_id).first()
            if not db_vuln:
                # Extract severity if available
                severity = "Medium" # Default
                # OSV usually has 'severity' field list, e.g. [{"type": "CVSS_V3", "score": "..."}]
                
                db_vuln = models.Vulnerability(
                    id=v_id,
                    source="OSV",
                    severity=severity, 
                    description=v.get("summary", "No description"),
                    affected_packages=v.get("affected"),
                    published_at=datetime.utcnow() # Should parse 'published' field
                )
                db.add(db_vuln)
                db.commit()
                db.refresh(db_vuln)

            # 2. Link to Asset (if asset_id provided)
            if asset_id:
                # Check for existing link
                # Constraint: We need asset_type and scan_id to link to Asset Table correctly.
                # For MVP, we might receive these or look them up.
                # If asset_id is just a string, we assume it's the specific asset.
                pass 
                # Implementing AssetVulnerability creation requires more context (scan_id etc).
                # For this function, we will return the vulnerability objects found.
            
            found_vulns.append(db_vuln)

    return found_vulns
