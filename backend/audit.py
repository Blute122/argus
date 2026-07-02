"""Audit logging helper.

Explicit calls at security-relevant points (not blanket middleware) so the
audit trail stays high-signal: authn, authz-gated changes, and admin actions.
"""

from fastapi import Request

from backend.database.connection import SessionLocal
from backend.models.audit_log import AuditLog


def client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def record(action: str, *, actor=None, actor_username: str | None = None,
           target_type: str | None = None, target_id=None, detail: str | None = None,
           request: Request | None = None, outcome: str = "success", db=None) -> None:
    """Write one audit entry. Never raises — auditing must not break requests."""
    own_session = db is None
    session = db or SessionLocal()
    try:
        session.add(AuditLog(
            actor_id=getattr(actor, "id", None),
            actor_username=actor_username or getattr(actor, "username", None),
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            detail=detail,
            source_ip=client_ip(request),
            outcome=outcome,
        ))
        session.commit()
    except Exception:
        try:
            session.rollback()
        except Exception:
            pass
    finally:
        if own_session:
            session.close()
