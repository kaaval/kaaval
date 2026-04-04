"""
Widget canvas dashboard API — persists layout and widget config per user.
"""
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, database, auth

router = APIRouter(
    prefix="/api/v1/dashboards",
    tags=["dashboards"],
    dependencies=[Depends(auth.get_current_active_user)],
)


# ── Schemas ────────────────────────────────────────────────────────────────────

class WidgetCreate(BaseModel):
    widget_type: str
    title: Optional[str] = None
    grid_x: int = 0
    grid_y: int = 0
    grid_w: int = 2
    grid_h: int = 2
    config: dict = {}


class WidgetUpdate(BaseModel):
    title: Optional[str] = None
    config: Optional[dict] = None


class GridPosition(BaseModel):
    id: str
    grid_x: int
    grid_y: int
    grid_w: int
    grid_h: int


class LayoutUpdate(BaseModel):
    positions: List[GridPosition]


class DashboardCreate(BaseModel):
    name: str
    is_default: bool = False


class DashboardSchema(BaseModel):
    id: str
    name: str
    is_default: bool
    created_at: datetime
    updated_at: datetime


# ── Dashboards ─────────────────────────────────────────────────────────────────

@router.get("", response_model=List[DashboardSchema])
def list_dashboards(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    rows = db.query(models.DashboardLayout).filter(
        models.DashboardLayout.user_id == current_user.id
    ).all()
    return [
        {"id": str(r.id), "name": r.name, "is_default": r.is_default,
         "created_at": r.created_at, "updated_at": r.updated_at}
        for r in rows
    ]


@router.post("")
def create_dashboard(
    body: DashboardCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    if body.is_default:
        # Unset any existing default for this user
        db.query(models.DashboardLayout).filter(
            models.DashboardLayout.user_id == current_user.id,
            models.DashboardLayout.is_default == True,
        ).update({"is_default": False})

    dashboard = models.DashboardLayout(
        id=uuid.uuid4(),
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        name=body.name,
        is_default=body.is_default,
    )
    db.add(dashboard)
    db.commit()
    db.refresh(dashboard)

    # Seed with 4 starter widgets for new dashboards
    if not db.query(models.DashboardLayout).filter(
        models.DashboardLayout.user_id == current_user.id
    ).count() > 1:
        _seed_starter_widgets(dashboard.id, db)

    return {"id": str(dashboard.id), "name": dashboard.name}


def _seed_starter_widgets(dashboard_id: uuid.UUID, db: Session):
    starters = [
        {"widget_type": "stat_card", "title": "Total Assets", "grid_x": 0, "grid_y": 0, "grid_w": 2, "grid_h": 2, "config": {"metric": "total_assets"}},
        {"widget_type": "stat_card", "title": "Open CVEs", "grid_x": 2, "grid_y": 0, "grid_w": 2, "grid_h": 2, "config": {"metric": "open_cves"}},
        {"widget_type": "stat_card", "title": "Online Endpoints", "grid_x": 4, "grid_y": 0, "grid_w": 2, "grid_h": 2, "config": {"metric": "online_endpoints"}},
        {"widget_type": "alert_feed", "title": "Recent Findings", "grid_x": 0, "grid_y": 2, "grid_w": 6, "grid_h": 4, "config": {}},
    ]
    for s in starters:
        db.add(models.WidgetInstance(id=uuid.uuid4(), dashboard_id=dashboard_id, **s))
    db.commit()


@router.get("/{dashboard_id}")
def get_dashboard(
    dashboard_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    dashboard = db.query(models.DashboardLayout).filter(
        models.DashboardLayout.id == dashboard_id,
        models.DashboardLayout.user_id == current_user.id,
    ).first()
    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")

    widgets = db.query(models.WidgetInstance).filter(
        models.WidgetInstance.dashboard_id == dashboard_id
    ).all()

    return {
        "id": str(dashboard.id),
        "name": dashboard.name,
        "is_default": dashboard.is_default,
        "updated_at": dashboard.updated_at,
        "widgets": [
            {
                "id": str(w.id),
                "widget_type": w.widget_type,
                "title": w.title,
                "grid_x": w.grid_x,
                "grid_y": w.grid_y,
                "grid_w": w.grid_w,
                "grid_h": w.grid_h,
                "config": w.config,
            }
            for w in widgets
        ],
    }


@router.delete("/{dashboard_id}")
def delete_dashboard(
    dashboard_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    dashboard = db.query(models.DashboardLayout).filter(
        models.DashboardLayout.id == dashboard_id,
        models.DashboardLayout.user_id == current_user.id,
    ).first()
    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    db.delete(dashboard)
    db.commit()
    return {"message": "Deleted"}


# ── Layout (batch grid position update) ───────────────────────────────────────

@router.patch("/{dashboard_id}/layout")
def save_layout(
    dashboard_id: uuid.UUID,
    body: LayoutUpdate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    dashboard = db.query(models.DashboardLayout).filter(
        models.DashboardLayout.id == dashboard_id,
        models.DashboardLayout.user_id == current_user.id,
    ).first()
    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")

    for pos in body.positions:
        widget = db.query(models.WidgetInstance).filter(
            models.WidgetInstance.id == uuid.UUID(pos.id),
            models.WidgetInstance.dashboard_id == dashboard_id,
        ).first()
        if widget:
            widget.grid_x = pos.grid_x
            widget.grid_y = pos.grid_y
            widget.grid_w = pos.grid_w
            widget.grid_h = pos.grid_h

    dashboard.updated_at = datetime.utcnow()
    db.commit()
    return {"message": "Layout saved"}


# ── Widgets ────────────────────────────────────────────────────────────────────

@router.post("/{dashboard_id}/widgets")
def add_widget(
    dashboard_id: uuid.UUID,
    body: WidgetCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    dashboard = db.query(models.DashboardLayout).filter(
        models.DashboardLayout.id == dashboard_id,
        models.DashboardLayout.user_id == current_user.id,
    ).first()
    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")

    widget = models.WidgetInstance(
        id=uuid.uuid4(),
        dashboard_id=dashboard_id,
        widget_type=body.widget_type,
        title=body.title,
        grid_x=body.grid_x,
        grid_y=body.grid_y,
        grid_w=body.grid_w,
        grid_h=body.grid_h,
        config=body.config,
    )
    db.add(widget)
    db.commit()
    db.refresh(widget)
    return {"id": str(widget.id), "message": "Widget added"}


@router.patch("/{dashboard_id}/widgets/{widget_id}")
def update_widget(
    dashboard_id: uuid.UUID,
    widget_id: uuid.UUID,
    body: WidgetUpdate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    widget = db.query(models.WidgetInstance).filter(
        models.WidgetInstance.id == widget_id,
        models.WidgetInstance.dashboard_id == dashboard_id,
    ).first()
    if not widget:
        raise HTTPException(status_code=404, detail="Widget not found")
    if body.title is not None:
        widget.title = body.title
    if body.config is not None:
        widget.config = body.config
    db.commit()
    return {"message": "Widget updated"}


@router.delete("/{dashboard_id}/widgets/{widget_id}")
def delete_widget(
    dashboard_id: uuid.UUID,
    widget_id: uuid.UUID,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user),
):
    widget = db.query(models.WidgetInstance).filter(
        models.WidgetInstance.id == widget_id,
        models.WidgetInstance.dashboard_id == dashboard_id,
    ).first()
    if not widget:
        raise HTTPException(status_code=404, detail="Widget not found")
    db.delete(widget)
    db.commit()
    return {"message": "Widget removed"}
