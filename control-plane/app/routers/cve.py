"""CVE Feed router — manage feeds, run cluster scans, browse CVE entries."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from ..database import get_db
from ..auth import get_current_active_user
from ..models import CVEFeed, CVEEntry
from ..cve_service import cve_service

router = APIRouter(prefix="/cve", tags=["CVE"])


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class FeedCreate(BaseModel):
    name: str
    url: str
    feed_type: str = "auto"          # auto | json_feed | osv | nvd
    description: Optional[str] = None


# ── Feed management ────────────────────────────────────────────────────────────

@router.get("/feeds")
def list_feeds(db: Session = Depends(get_db), user=Depends(get_current_active_user)):
    """List all configured CVE feeds."""
    feeds = db.query(CVEFeed).order_by(CVEFeed.created_at).all()
    return [
        {
            "id": str(f.id),
            "name": f.name,
            "url": f.url,
            "feed_type": f.feed_type,
            "description": f.description,
            "enabled": f.enabled,
            "last_fetched": f.last_fetched.isoformat() if f.last_fetched else None,
            "entry_count": f.entry_count,
        }
        for f in feeds
    ]


@router.post("/feeds", status_code=201)
def add_feed(
    body: FeedCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Add a new CVE feed (Kubernetes official, OSV, NVD, or any compatible JSON endpoint)."""
    if db.query(CVEFeed).filter(CVEFeed.name == body.name).first():
        raise HTTPException(400, f"A feed named '{body.name}' already exists.")
    feed = CVEFeed(
        name=body.name,
        url=body.url,
        feed_type=body.feed_type,
        description=body.description,
    )
    db.add(feed)
    db.commit()
    db.refresh(feed)
    return {
        "id": str(feed.id),
        "name": feed.name,
        "message": "Feed added. POST /cve/feeds/{id}/refresh to load CVEs.",
    }


@router.delete("/feeds/{feed_id}")
def delete_feed(
    feed_id: UUID,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Delete a feed and all its CVE entries."""
    feed = db.query(CVEFeed).filter(CVEFeed.id == feed_id).first()
    if not feed:
        raise HTTPException(404, "Feed not found.")
    db.delete(feed)
    db.commit()
    return {"message": f"Feed '{feed.name}' and all its entries deleted."}


@router.patch("/feeds/{feed_id}/toggle")
def toggle_feed(
    feed_id: UUID,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Enable or disable a feed without deleting it."""
    feed = db.query(CVEFeed).filter(CVEFeed.id == feed_id).first()
    if not feed:
        raise HTTPException(404, "Feed not found.")
    feed.enabled = not feed.enabled
    db.commit()
    return {"id": str(feed.id), "name": feed.name, "enabled": feed.enabled}


@router.post("/feeds/{feed_id}/refresh")
async def refresh_feed(
    feed_id: UUID,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Fetch and reload CVE data for a single feed."""
    feed = db.query(CVEFeed).filter(CVEFeed.id == feed_id).first()
    if not feed:
        raise HTTPException(404, "Feed not found.")
    try:
        return await cve_service.refresh_feed(feed_id, db)
    except Exception as e:
        raise HTTPException(502, f"Feed fetch failed: {e}")


@router.post("/feeds/refresh-all")
async def refresh_all_feeds(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Fetch and reload CVE data for all enabled feeds."""
    results = await cve_service.refresh_all_feeds(db)
    return {"results": results}


# ── CVE entry browser ──────────────────────────────────────────────────────────

@router.get("/entries")
def list_entries(
    severity: Optional[str] = None,
    feed_id: Optional[UUID] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Browse all CVE entries with optional filters."""
    q = db.query(CVEEntry).join(CVEFeed).filter(CVEFeed.enabled == True)
    if severity:
        q = q.filter(CVEEntry.severity == severity.upper())
    if feed_id:
        q = q.filter(CVEEntry.feed_id == feed_id)
    if search:
        pattern = f"%{search}%"
        q = q.filter(CVEEntry.cve_id.ilike(pattern) | CVEEntry.title.ilike(pattern))

    total = q.count()
    entries = q.order_by(CVEEntry.published_date.desc().nullslast()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "entries": [
            {
                "id": str(e.id),
                "feed_id": str(e.feed_id),
                "cve_id": e.cve_id,
                "title": e.title,
                "severity": e.severity,
                "cvss_score": e.cvss_score,
                "published_date": e.published_date.isoformat() if e.published_date else None,
                "fixed_in": e.fixed_in,
                "references": (e.references or [])[:3],
            }
            for e in entries
        ],
    }


# ── Cluster scan ───────────────────────────────────────────────────────────────

@router.post("/scan")
def run_scan(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Scan the live cluster against all CVEs in enabled feeds."""
    return cve_service.scan_cluster(db)


@router.get("/scan/latest")
def get_latest_scan(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Return the most recent cluster scan result."""
    result = cve_service.get_latest_scan(db)
    if not result:
        return {"message": "No scan results yet. POST /cve/scan to run the first scan."}
    return result


# ── Summary ────────────────────────────────────────────────────────────────────

@router.get("/summary")
def get_summary(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Quick dashboard summary: feed stats, total CVE count, severity breakdown, latest scan."""
    feeds = db.query(CVEFeed).all()
    total_entries = db.query(CVEEntry).count()
    severity_counts = {
        sev: db.query(CVEEntry).filter(CVEEntry.severity == sev).count()
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    }
    return {
        "feeds": len(feeds),
        "total_cves": total_entries,
        "severity_breakdown": severity_counts,
        "latest_scan": cve_service.get_latest_scan(db),
    }
