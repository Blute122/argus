"""Logs API and threat hunting query endpoints."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_, and_
from pydantic import BaseModel
from typing import Optional
from backend.database.connection import get_db
from backend.models.log import Log
from backend.models.hunt_query import HuntQuery
from backend.models.user import User
from backend.api.auth import get_current_user

router = APIRouter(prefix="/api", tags=["Logs & Hunting"])


@router.get("/logs")
def get_logs(
    source: Optional[str] = None, event_type: Optional[str] = None,
    severity: Optional[str] = None, limit: int = Query(default=100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db), _user=Depends(get_current_user),
):
    q = db.query(Log).order_by(desc(Log.timestamp))
    if source:
        q = q.filter(Log.source == source)
    if event_type:
        q = q.filter(Log.event_type == event_type)
    if severity:
        q = q.filter(Log.severity == severity)
    logs = q.offset(offset).limit(limit).all()
    return [_fmt_log(l) for l in logs]


@router.get("/logs/stats")
def get_log_stats(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    total = db.query(func.count(Log.id)).scalar()
    by_source = dict(db.query(Log.source, func.count(Log.id)).group_by(Log.source).all())
    by_severity = dict(db.query(Log.severity, func.count(Log.id)).group_by(Log.severity).all())
    return {"total": total, "by_source": by_source, "by_severity": by_severity}


@router.post("/hunt")
def run_hunt_query(query: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Parse a Splunk-like query and search logs."""
    results = _parse_and_search(query, db)
    # Save query history
    hq = HuntQuery(name=f"Hunt: {query[:50]}", query=query, created_by=user.id, results_count=len(results))
    db.add(hq)
    db.commit()
    return {"query": query, "results_count": len(results), "results": results[:200]}


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


def _parse_and_search(query: str, db: Session) -> list:
    """Simple Splunk-like query parser: source=windows eventid=4625 etc."""
    q = db.query(Log).order_by(desc(Log.timestamp))
    parts = query.strip().split()
    for part in parts:
        if "=" in part:
            field, value = part.split("=", 1)
            field = field.lower().strip()
            value = value.strip().strip('"').strip("'")
            if field == "source":
                q = q.filter(Log.source == value)
            elif field in ("eventid", "event_id"):
                q = q.filter(Log.event_id == value)
            elif field == "event_type":
                q = q.filter(Log.event_type == value)
            elif field == "severity":
                q = q.filter(Log.severity == value)
            elif field in ("source_ip", "src_ip"):
                q = q.filter(Log.source_ip == value)
            elif field in ("dest_ip", "destination_ip", "dst_ip"):
                q = q.filter(Log.destination_ip == value)
            elif field in ("hostname", "host"):
                q = q.filter(Log.hostname == value)
            elif field in ("username", "user"):
                q = q.filter(Log.username == value)
            elif field in ("process_name", "process"):
                q = q.filter(Log.process_name.ilike(f"%{value}%"))
            elif field in ("destination_port", "dest_port", "port"):
                q = q.filter(Log.destination_port == int(value))
            elif field in ("command_line", "cmd"):
                q = q.filter(Log.command_line.ilike(f"%{value}%"))
            elif field in ("dns_query", "dns"):
                q = q.filter(Log.dns_query.ilike(f"%{value}%"))
            elif field in ("mitre_technique",):
                q = q.filter(Log.mitre_technique == value)
        else:
            # Free text search in raw_log
            q = q.filter(Log.raw_log.ilike(f"%{part}%"))
    results = q.limit(200).all()
    return [_fmt_log(l) for l in results]


def _fmt_log(l):
    return {
        "id": l.id, "timestamp": str(l.timestamp), "source": l.source,
        "source_ip": l.source_ip, "destination_ip": l.destination_ip,
        "event_type": l.event_type, "event_id": l.event_id,
        "severity": l.severity, "hostname": l.hostname, "username": l.username,
        "process_name": l.process_name, "command_line": l.command_line,
        "raw_log": l.raw_log, "mitre_tactic": l.mitre_tactic,
        "mitre_technique": l.mitre_technique, "dns_query": l.dns_query,
        "destination_port": l.destination_port, "is_malicious": l.is_malicious,
    }
