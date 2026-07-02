"""Audit log query API (admin only)."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from backend.api.auth import require_roles
from backend.database.connection import get_db
from backend.models.audit_log import AuditLog

router = APIRouter(prefix="/api/audit", tags=["Audit"])


@router.get("")
def list_audit(
    action: str | None = None,
    actor: str | None = None,
    outcome: str | None = None,
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_db),
    _admin=Depends(require_roles(["admin"])),
):
    q = db.query(AuditLog).order_by(desc(AuditLog.timestamp))
    if action:
        q = q.filter(AuditLog.action == action)
    if actor:
        q = q.filter(AuditLog.actor_username == actor)
    if outcome:
        q = q.filter(AuditLog.outcome == outcome)
    rows = q.limit(limit).all()
    return [{
        "id": r.id,
        "timestamp": str(r.timestamp),
        "actor": r.actor_username,
        "action": r.action,
        "target_type": r.target_type,
        "target_id": r.target_id,
        "detail": r.detail,
        "source_ip": r.source_ip,
        "outcome": r.outcome,
    } for r in rows]
