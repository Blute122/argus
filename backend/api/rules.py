"""Detection rule management API."""

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.api.auth import get_current_user, require_roles
from backend.database.connection import get_db
from backend.detection.engine import detection_engine
from backend.models.detection_rule import DetectionRule
from backend.search import get_log_store

router = APIRouter(prefix="/api/detection", tags=["Detection Rules"])

_MANAGE = require_roles(["admin", "threat_hunter"])


def _serialize(row: DetectionRule) -> dict:
    return {
        "id": row.id,
        "title": row.title,
        "description": row.description,
        "rule_type": row.rule_type,
        "severity": row.severity,
        "mitre_technique": row.mitre_technique,
        "tags": _json_list(row.tags),
        "source": row.source,
        "enabled": bool(row.enabled),
        "match_count": row.match_count or 0,
        "last_fired_at": str(row.last_fired_at) if row.last_fired_at else None,
    }


@router.get("/rules")
def list_rules(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    rows = db.query(DetectionRule).order_by(DetectionRule.severity.desc(), DetectionRule.title).all()
    return [_serialize(r) for r in rows]


@router.get("/rules/{rule_id}")
def get_rule(rule_id: str, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    row = db.get(DetectionRule, rule_id)
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")
    payload = _serialize(row)
    rule = detection_engine.get_rule(rule_id)
    if rule and getattr(rule, "path", None):
        try:
            with open(rule.path, "r", encoding="utf-8") as fh:
                payload["yaml"] = fh.read()
        except OSError:
            payload["yaml"] = None
    return payload


@router.post("/rules/{rule_id}/enable")
def enable_rule(rule_id: str, _user=Depends(_MANAGE)):
    if not detection_engine.set_enabled(rule_id, True):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"id": rule_id, "enabled": True}


@router.post("/rules/{rule_id}/disable")
def disable_rule(rule_id: str, _user=Depends(_MANAGE)):
    if not detection_engine.set_enabled(rule_id, False):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"id": rule_id, "enabled": False}


@router.post("/rules/{rule_id}/test")
def test_rule(rule_id: str, _user=Depends(_MANAGE)):
    """Dry-run a rule against recent logs without persisting alerts."""
    rule = detection_engine.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found or not loaded")
    store = get_log_store()

    if rule.rule_type == "threshold":
        alerts = rule.evaluate(store)
        return {"id": rule_id, "type": "threshold", "matches": len(alerts), "sample": alerts[:5]}

    sample_logs = store.search_logs(limit=500)
    matches = [log for log in sample_logs if rule.matches(log)]
    return {
        "id": rule_id, "type": "streaming",
        "scanned": len(sample_logs), "matches": len(matches),
        "sample": matches[:5],
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
