"""Incidents API endpoints for IR workflow."""
import json
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from typing import Optional
from backend import audit
from backend.database.connection import get_db
from backend.models.alert import Alert
from backend.models.asset import Asset
from backend.models.incident import Incident, IncidentNote
from backend.models.log import Log
from backend.models.user import User
from backend.api.auth import get_current_user
from backend.utils.threat_intel import analyze_ip
from backend.api.auth import require_roles

# Roles allowed to change incident state (admin bypasses via require_roles).
_IR_ROLES = ["analyst_l2", "analyst_l3", "incident_responder"]

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


class EvidenceCreate(BaseModel):
    title: str
    evidence_type: str = "artifact"
    value: str
    description: Optional[str] = None


@router.get("/")
def get_incidents(status: Optional[str] = None, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    q = db.query(Incident).order_by(desc(Incident.created_at))
    if status:
        q = q.filter(Incident.status == status)
    incidents = q.limit(200).all()
    return [_format_incident(i) for i in incidents]


@router.get("/stats")
def get_incident_stats(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    from sqlalchemy import func
    total = db.query(func.count(Incident.id)).scalar()
    by_status = dict(db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all())
    by_severity = dict(db.query(Incident.severity, func.count(Incident.id)).group_by(Incident.severity).all())
    return {"total": total, "by_status": by_status, "by_severity": by_severity}


@router.get("/{incident_id}")
def get_incident_detail(incident_id: int, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    payload = _format_incident(incident)
    payload["notes"] = _get_notes_payload(incident_id, db)
    payload["timeline"] = _get_timeline_payload(incident, db)
    payload["alerts"] = [_format_alert(a) for a in db.query(Alert).filter(Alert.incident_id == incident_id).order_by(desc(Alert.timestamp)).all()]
    payload["related_assets"] = _get_related_assets(incident, db)
    return payload


@router.post("/")
def create_incident(data: IncidentCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    sla_hours = SLA_HOURS.get(data.severity, 24)
    incident = Incident(
        title=data.title, description=data.description, severity=data.severity,
        category=data.category, assigned_to=data.assigned_to, created_by=user.id,
        sla_deadline=datetime.now(timezone.utc) + timedelta(hours=sla_hours),
    )
    db.add(incident)
    db.flush()
    db.add(IncidentNote(
        incident_id=incident.id,
        author_id=user.id,
        note_type="timeline",
        content=f"Incident created with severity {data.severity}",
    ))
    db.commit()
    db.refresh(incident)
    return _format_incident(incident)


@router.patch("/{incident_id}/status")
def update_status(incident_id: int, status: str, request: Request,
                  db: Session = Depends(get_db), user: User = Depends(require_roles(_IR_ROLES))):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = status
    if status == "resolved":
        incident.resolved_at = datetime.now(timezone.utc)
    if status == "closed":
        incident.closed_at = datetime.now(timezone.utc)
    db.add(IncidentNote(
        incident_id=incident_id,
        author_id=user.id,
        note_type="timeline",
        content=f"Status changed to {status}",
    ))
    db.commit()
    audit.record("incident.status_change", actor=user, target_type="incident",
                 target_id=incident_id, detail=f"status={status}", request=request, db=db)
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


@router.post("/{incident_id}/evidence")
def add_evidence(incident_id: int, data: EvidenceCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    evidence = _json_list(incident.evidence)
    item = {
        "id": len(evidence) + 1,
        "title": data.title,
        "type": data.evidence_type,
        "value": data.value,
        "description": data.description,
        "added_by": user.id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    evidence.append(item)
    incident.evidence = json.dumps(evidence)
    db.add(IncidentNote(
        incident_id=incident_id,
        author_id=user.id,
        note_type="evidence",
        content=f"Evidence added: {data.title}",
    ))
    db.commit()
    return item


@router.get("/{incident_id}/notes")
def get_notes(incident_id: int, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    return _get_notes_payload(incident_id, db)


@router.get("/{incident_id}/timeline")
def get_timeline(incident_id: int, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _get_timeline_payload(incident, db)


@router.post("/{incident_id}/enrich")
def enrich_incident(incident_id: int, db: Session = Depends(get_db), _user=Depends(require_roles(['threat_hunter', 'incident_responder', 'admin']))):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = db.query(Alert).filter(Alert.incident_id == incident.id).all()
    ips_to_check = set()
    
    for alert in alerts:
        if alert.source_ip: ips_to_check.add(alert.source_ip)
        if alert.destination_ip: ips_to_check.add(alert.destination_ip)

    if incident.ioc_list:
        try:
            iocs = json.loads(incident.ioc_list)
            for ioc in iocs:
                if isinstance(ioc, str) and "." in ioc:
                    ips_to_check.add(ioc)
        except:
            pass

    results = []
    evidence_added = 0
    
    import re
    ip_pattern = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
    ips_to_check.update(ip_pattern.findall(incident.description))
    ips_to_check.update(ip_pattern.findall(incident.title))

    for ip in ips_to_check:
        if ip and not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.")):
            ti_data = analyze_ip(ip)
            results.append(ti_data)

            if ti_data["status"] in ["malicious", "suspicious"]:
                note_content = f"**Threat Intel Automated Enrichment**\n**IP:** {ip}\n**Status:** {ti_data['status'].upper()}\n**Confidence:** {ti_data.get('confidence', 0)}%\n**Tags:** {', '.join(ti_data['tags'])}"
                existing = db.query(IncidentNote).filter(
                    IncidentNote.incident_id == incident.id,
                    IncidentNote.content.contains(f"IP:** {ip}")
                ).first()
                if not existing:
                    new_evidence = IncidentNote(incident_id=incident.id, author_id=_user.id, content=note_content, note_type="evidence")
                    db.add(new_evidence)
                    evidence_added += 1

    db.commit()
    return {"message": "Enrichment complete", "ips_checked": len(ips_to_check), "evidence_added": evidence_added, "findings": results}


def _format_incident(i):
    return {
        "id": i.id, "title": i.title, "description": i.description, "severity": i.severity,
        "status": i.status, "priority": i.priority, "category": i.category,
        "assigned_to": i.assigned_to, "created_by": i.created_by,
        "created_at": str(i.created_at), "updated_at": str(i.updated_at),
        "sla_deadline": str(i.sla_deadline) if i.sla_deadline else None,
        "resolved_at": str(i.resolved_at) if i.resolved_at else None,
        "evidence": _json_list(i.evidence),
        "affected_assets": _json_list(i.affected_assets),
        "mitre_techniques": _json_list(i.mitre_techniques),
        "ioc_list": _json_list(i.ioc_list),
        "alert_count": i.alert_count,
    }


def _json_list(value):
    if not value: return []
    if isinstance(value, list): return value
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except (TypeError, json.JSONDecodeError):
        return []


def _get_notes_payload(incident_id: int, db: Session):
    notes = db.query(IncidentNote).filter(IncidentNote.incident_id == incident_id).order_by(IncidentNote.created_at).all()
    return [{"id": n.id, "content": n.content, "note_type": n.note_type, "author_id": n.author_id, "created_at": str(n.created_at)} for n in notes]


def _get_timeline_payload(incident: Incident, db: Session):
    events = [
        {"type": "created", "title": "Incident created", "timestamp": str(incident.created_at), "detail": incident.title},
    ]
    for alert in db.query(Alert).filter(Alert.incident_id == incident.id).order_by(Alert.timestamp).all():
        events.append({
            "type": "alert", "title": f"Alert attached: {alert.title}",
            "timestamp": str(alert.timestamp), "detail": alert.rule_name, "severity": alert.severity,
        })
    for note in db.query(IncidentNote).filter(IncidentNote.incident_id == incident.id).order_by(IncidentNote.created_at).all():
        events.append({
            "type": note.note_type, "title": note.content,
            "timestamp": str(note.created_at), "detail": f"Author #{note.author_id}",
        })
    if incident.resolved_at:
        events.append({"type": "resolved", "title": "Incident resolved", "timestamp": str(incident.resolved_at), "detail": incident.resolution_summary})
    if incident.closed_at:
        events.append({"type": "closed", "title": "Incident closed", "timestamp": str(incident.closed_at), "detail": incident.resolution_summary})
    return sorted(events, key=lambda item: item.get("timestamp") or "")


def _get_related_assets(incident: Incident, db: Session):
    identifiers = set(_json_list(incident.affected_assets) + _json_list(incident.ioc_list))
    if not identifiers:
        alerts = db.query(Alert).filter(Alert.incident_id == incident.id).all()
        for alert in alerts:
            identifiers.update(value for value in [alert.hostname, alert.source_ip, alert.destination_ip] if value)
    assets = []
    for asset in db.query(Asset).all():
        if asset.hostname in identifiers or asset.ip_address in identifiers:
            assets.append({
                "id": asset.id, "hostname": asset.hostname, "ip_address": asset.ip_address,
                "criticality": asset.criticality, "risk_score": asset.risk_score, "status": asset.status,
            })
    return assets


def _format_alert(alert: Alert):
    return {
        "id": alert.id, "title": alert.title, "severity": alert.severity, "status": alert.status,
        "timestamp": str(alert.timestamp), "source_ip": alert.source_ip, "destination_ip": alert.destination_ip,
        "hostname": alert.hostname, "mitre_technique": alert.mitre_technique, "rule_name": alert.rule_name,
    }
