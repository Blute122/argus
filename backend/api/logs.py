"""Logs API and threat hunting query endpoints."""
import json
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from typing import Optional, Union
from backend.database.connection import get_db
from backend.models.incident import Incident, IncidentNote
from backend.models.hunt_query import HuntQuery
from backend.models.user import User
from backend.api.auth import get_current_user
from backend.search import get_log_store

router = APIRouter(prefix="/api", tags=["Logs & Hunting"])

SLA_HOURS = {"critical": 4, "high": 8, "medium": 24, "low": 72}


# Log ids are ints (SQL fallback) or strings (OpenSearch doc ids).
LogId = Union[int, str]


class HuntIncidentCreate(BaseModel):
    query: str
    log_ids: list[LogId]
    title: str
    severity: str = "medium"
    category: str = "threat_hunt"
    description: Optional[str] = None


class HuntAttachRequest(BaseModel):
    query: str
    log_ids: list[LogId]


@router.get("/logs")
def get_logs(
    source: Optional[str] = None, event_type: Optional[str] = None,
    severity: Optional[str] = None, limit: int = Query(default=100, le=1000),
    offset: int = 0,
    _user=Depends(get_current_user),
):
    return get_log_store().search_logs(
        source=source, event_type=event_type, severity=severity, limit=limit, offset=offset
    )


@router.get("/logs/stats")
def get_log_stats(_user=Depends(get_current_user)):
    return get_log_store().log_stats()


@router.post("/hunt")
def run_hunt_query(query: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Parse an advanced SPL/KQL-like query and search logs."""
    formatted = get_log_store().hunt(query, limit=500)

    # Save query history
    hq = HuntQuery(name=f"Hunt: {query[:50]}", query=query, created_by=user.id, results_count=len(formatted))
    db.add(hq)
    db.commit()

    return {
        "query": query,
        "results_count": len(formatted),
        "results": formatted[:200],
        "fields": ["source", "event_id", "event_type", "severity", "hostname", "username", "process_name", "source_ip", "destination_ip", "destination_port", "mitre_technique", "dns_query"],
        "syntax": ["AND", "OR", "NOT", "* wildcard", "earliest=-24h", "latest=YYYY-MM-DDTHH:MM:SS"],
    }


@router.post("/hunt/create-incident")
def create_incident_from_hunt(data: HuntIncidentCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    logs = _get_selected_logs(data.log_ids)
    if not logs:
        raise HTTPException(status_code=400, detail="No matching logs selected")

    assets = sorted({value for log in logs for value in [log.hostname, log.source_ip, log.destination_ip] if value})
    mitre = sorted({log.mitre_technique for log in logs if log.mitre_technique})
    iocs = sorted({value for log in logs for value in [log.source_ip, log.destination_ip, log.dns_query, log.url] if value})
    evidence = [_log_evidence(log, data.query) for log in logs]

    incident = Incident(
        title=data.title,
        description=data.description or f"Threat hunt escalation from query: {data.query}",
        severity=data.severity,
        category=data.category,
        assigned_to=user.id,
        created_by=user.id,
        sla_deadline=datetime.now(timezone.utc) + timedelta(hours=SLA_HOURS.get(data.severity, 24)),
        evidence=json.dumps(evidence),
        affected_assets=json.dumps(assets),
        mitre_techniques=json.dumps(mitre),
        ioc_list=json.dumps(iocs),
        alert_count=0,
    )
    db.add(incident)
    db.flush()
    db.add(IncidentNote(
        incident_id=incident.id,
        author_id=user.id,
        note_type="timeline",
        content=f"Incident created from threat hunt query: {data.query}",
    ))
    db.commit()
    db.refresh(incident)
    return {"message": "Incident created from hunt", "incident_id": incident.id, "logs_attached": len(logs)}


@router.post("/hunt/attach-incident/{incident_id}")
def attach_hunt_to_incident(incident_id: int, data: HuntAttachRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    logs = _get_selected_logs(data.log_ids)
    if not logs:
        raise HTTPException(status_code=400, detail="No matching logs selected")

    evidence = _json_list(incident.evidence)
    evidence.extend(_log_evidence(log, data.query) for log in logs)
    incident.evidence = json.dumps(evidence)

    incident.affected_assets = json.dumps(sorted(set(_json_list(incident.affected_assets)) | {value for log in logs for value in [log.hostname, log.source_ip, log.destination_ip] if value}))
    incident.mitre_techniques = json.dumps(sorted(set(_json_list(incident.mitre_techniques)) | {log.mitre_technique for log in logs if log.mitre_technique}))
    incident.ioc_list = json.dumps(sorted(set(_json_list(incident.ioc_list)) | {value for log in logs for value in [log.source_ip, log.destination_ip, log.dns_query, log.url] if value}))
    db.add(IncidentNote(
        incident_id=incident_id,
        author_id=user.id,
        note_type="evidence",
        content=f"Attached {len(logs)} hunt result logs from query: {data.query}",
    ))
    db.commit()
    return {"message": "Hunt results attached", "incident_id": incident_id, "logs_attached": len(logs)}


@router.get("/hunts/history")
def get_hunt_history(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    queries = db.query(HuntQuery).order_by(desc(HuntQuery.created_at)).limit(50).all()
    return [{"id": q.id, "name": q.name, "query": q.query, "results_count": q.results_count,
             "created_at": str(q.created_at)} for q in queries]


@router.get("/hunts/saved")
def get_saved_hunts(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    queries = db.query(HuntQuery).filter(HuntQuery.is_saved == 1).order_by(desc(HuntQuery.created_at)).all()
    return [{"id": q.id, "name": q.name, "query": q.query, "results_count": q.results_count} for q in queries]


@router.post("/hunts/{hunt_id}/save")
def save_hunt(hunt_id: int, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    hunt = db.query(HuntQuery).filter(HuntQuery.id == hunt_id).first()
    if hunt:
        hunt.is_saved = 1
        db.commit()
    return {"message": "Hunt saved"}


def _get_selected_logs(log_ids: list):
    return get_log_store().get_logs_by_ids(log_ids)


def _log_evidence(log: Log, query: str):
    return {
        "id": f"log-{log.id}",
        "title": f"Hunt log #{log.id}",
        "type": "log",
        "value": log.raw_log,
        "description": f"Selected from hunt query: {query}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {
            "log_id": log.id,
            "timestamp": str(log.timestamp),
            "source": log.source,
            "event_type": log.event_type,
            "severity": log.severity,
        },
    }


def _json_list(value):
    if not value:
        return []
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except (TypeError, json.JSONDecodeError):
        return []
