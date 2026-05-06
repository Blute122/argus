"""Alerts API endpoints."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from pydantic import BaseModel
from typing import Optional
from backend.database.connection import get_db
from backend.models.alert import Alert
from backend.api.auth import get_current_user

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


class AlertResponse(BaseModel):
    id: int
    timestamp: str
    title: str
    description: str
    severity: str
    status: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    rule_name: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    recommended_action: Optional[str] = None
    event_count: int = 1

    class Config:
        from_attributes = True


@router.get("/", response_model=list[AlertResponse])
def get_alerts(
    severity: Optional[str] = None, status: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
    db: Session = Depends(get_db), _user=Depends(get_current_user),
):
    q = db.query(Alert).order_by(desc(Alert.timestamp))
    if severity:
        q = q.filter(Alert.severity == severity)
    if status:
        q = q.filter(Alert.status == status)
    alerts = q.offset(offset).limit(limit).all()
    return [AlertResponse(
        id=a.id, timestamp=str(a.timestamp), title=a.title, description=a.description,
        severity=a.severity, status=a.status, source_ip=a.source_ip,
        destination_ip=a.destination_ip, rule_name=a.rule_name,
        mitre_tactic=a.mitre_tactic, mitre_technique=a.mitre_technique,
        mitre_technique_name=a.mitre_technique_name, hostname=a.hostname,
        username=a.username, recommended_action=a.recommended_action,
        event_count=a.event_count or 1,
    ) for a in alerts]


@router.get("/stats")
def get_alert_stats(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    total = db.query(func.count(Alert.id)).scalar()
    by_severity = dict(db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all())
    by_status = dict(db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all())
    return {"total": total, "by_severity": by_severity, "by_status": by_status}


@router.patch("/{alert_id}/status")
def update_alert_status(alert_id: int, status: str, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = status
    db.commit()
    return {"message": "Alert status updated", "id": alert_id, "status": status}
