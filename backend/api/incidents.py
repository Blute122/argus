"""Incidents API endpoints for IR workflow."""
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from typing import Optional
from backend.database.connection import get_db
from backend.models.incident import Incident, IncidentNote
from backend.models.user import User
from backend.api.auth import get_current_user

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])

SLA_HOURS = {"critical": 4, "high": 8, "medium": 24, "low": 72}


class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: str = "medium"
    category: Optional[str] = None
    assigned_to: Optional[int] = None


class NoteCreate(BaseModel):
    content: str
    note_type: str = "general"


@router.get("/")
def get_incidents(status: Optional[str] = None, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    q = db.query(Incident).order_by(desc(Incident.created_at))
    if status:
        q = q.filter(Incident.status == status)
    incidents = q.limit(200).all()
    return [_format_incident(i) for i in incidents]


@router.post("/")
def create_incident(data: IncidentCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    sla_hours = SLA_HOURS.get(data.severity, 24)
    incident = Incident(
        title=data.title, description=data.description, severity=data.severity,
        category=data.category, assigned_to=data.assigned_to, created_by=user.id,
        sla_deadline=datetime.now(timezone.utc) + timedelta(hours=sla_hours),
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return _format_incident(incident)


@router.patch("/{incident_id}/status")
def update_status(incident_id: int, status: str, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = status
    if status == "resolved":
        incident.resolved_at = datetime.now(timezone.utc)
    if status == "closed":
        incident.closed_at = datetime.now(timezone.utc)
    db.commit()
    return _format_incident(incident)


@router.post("/{incident_id}/notes")
def add_note(incident_id: int, data: NoteCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    note = IncidentNote(incident_id=incident_id, author_id=user.id, content=data.content, note_type=data.note_type)
    db.add(note)
    db.commit()
    db.refresh(note)
    return {"id": note.id, "content": note.content, "note_type": note.note_type, "created_at": str(note.created_at)}


@router.get("/{incident_id}/notes")
def get_notes(incident_id: int, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    notes = db.query(IncidentNote).filter(IncidentNote.incident_id == incident_id).order_by(IncidentNote.created_at).all()
    return [{"id": n.id, "content": n.content, "note_type": n.note_type, "author_id": n.author_id, "created_at": str(n.created_at)} for n in notes]


@router.get("/stats")
def get_incident_stats(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    from sqlalchemy import func
    total = db.query(func.count(Incident.id)).scalar()
    by_status = dict(db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all())
    by_severity = dict(db.query(Incident.severity, func.count(Incident.id)).group_by(Incident.severity).all())
    return {"total": total, "by_status": by_status, "by_severity": by_severity}


def _format_incident(i):
    return {
        "id": i.id, "title": i.title, "description": i.description, "severity": i.severity,
        "status": i.status, "priority": i.priority, "category": i.category,
        "assigned_to": i.assigned_to, "created_by": i.created_by,
        "created_at": str(i.created_at), "updated_at": str(i.updated_at),
        "sla_deadline": str(i.sla_deadline) if i.sla_deadline else None,
        "resolved_at": str(i.resolved_at) if i.resolved_at else None,
        "alert_count": i.alert_count,
    }
