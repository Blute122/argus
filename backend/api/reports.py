"""Analyst report generation endpoints."""

from datetime import datetime, timezone
import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.api.auth import get_current_user
from backend.database.connection import get_db
from backend.models.alert import Alert
from backend.models.asset import Asset
from backend.models.incident import Incident, IncidentNote

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/incident/{incident_id}")
def incident_report(incident_id: int, format: str = "markdown", db: Session = Depends(get_db), _user=Depends(get_current_user)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    payload = _report_payload(incident, db)
    if format == "json":
        return payload
    return {"incident_id": incident_id, "format": "markdown", "content": _to_markdown(payload)}


def _report_payload(incident: Incident, db: Session):
    alerts = db.query(Alert).filter(Alert.incident_id == incident.id).order_by(Alert.timestamp).all()
    notes = db.query(IncidentNote).filter(IncidentNote.incident_id == incident.id).order_by(IncidentNote.created_at).all()
    affected_assets = _json_list(incident.affected_assets)
    assets = []
    for asset in db.query(Asset).all():
        if asset.hostname in affected_assets or asset.ip_address in affected_assets:
            assets.append({
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "criticality": asset.criticality,
                "risk_score": asset.risk_score,
                "status": asset.status,
            })
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "category": incident.category,
            "created_at": str(incident.created_at),
            "sla_deadline": str(incident.sla_deadline) if incident.sla_deadline else None,
            "resolved_at": str(incident.resolved_at) if incident.resolved_at else None,
        },
        "executive_summary": _executive_summary(incident, alerts),
        "alerts": [{
            "id": alert.id,
            "title": alert.title,
            "severity": alert.severity,
            "rule_name": alert.rule_name,
            "timestamp": str(alert.timestamp),
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "hostname": alert.hostname,
            "mitre_technique": alert.mitre_technique,
        } for alert in alerts],
        "assets": assets,
        "iocs": _json_list(incident.ioc_list),
        "mitre_techniques": _json_list(incident.mitre_techniques),
        "evidence": _json_list(incident.evidence),
        "timeline": [{
            "type": note.note_type,
            "timestamp": str(note.created_at),
            "content": note.content,
        } for note in notes],
        "recommended_next_steps": _recommended_steps(incident),
    }


def _executive_summary(incident: Incident, alerts: list[Alert]):
    alert_count = len(alerts)
    techniques = sorted({alert.mitre_technique for alert in alerts if alert.mitre_technique})
    return (
        f"Incident INC-{incident.id} is a {incident.severity} severity {incident.category or 'security'} case "
        f"currently marked {incident.status}. The investigation contains {alert_count} attached alert(s)"
        f"{' and maps to ' + ', '.join(techniques) if techniques else ''}."
    )


def _recommended_steps(incident: Incident):
    base = [
        "Validate scope across related alerts, hunt results, and affected assets.",
        "Confirm whether containment is required for any high-risk asset.",
        "Preserve relevant telemetry and document analyst actions.",
    ]
    if incident.severity in {"critical", "high"}:
        base.insert(0, "Notify the incident commander and prioritize response within SLA.")
    if incident.status not in {"resolved", "closed"}:
        base.append("Define resolution criteria before closing the case.")
    return base


def _to_markdown(payload: dict):
    incident = payload["incident"]
    lines = [
        f"# Incident Report: INC-{incident['id']} - {incident['title']}",
        "",
        f"Generated: {payload['generated_at']}",
        "",
        "## Executive Summary",
        payload["executive_summary"],
        "",
        "## Case Details",
        f"- Severity: {incident['severity']}",
        f"- Status: {incident['status']}",
        f"- Category: {incident['category'] or 'Uncategorized'}",
        f"- Created: {incident['created_at']}",
        f"- SLA Deadline: {incident['sla_deadline'] or 'N/A'}",
        "",
        "## MITRE ATT&CK",
    ]
    lines.extend([f"- {tech}" for tech in payload["mitre_techniques"]] or ["- None recorded"])
    lines.extend(["", "## IOCs"])
    lines.extend([f"- {ioc}" for ioc in payload["iocs"]] or ["- None recorded"])
    lines.extend(["", "## Affected Assets"])
    lines.extend([f"- {asset['hostname']} ({asset['ip_address']}) - {asset['criticality']} / risk {asset['risk_score']}" for asset in payload["assets"]] or ["- None matched"])
    lines.extend(["", "## Attached Alerts"])
    lines.extend([f"- #{alert['id']} {alert['severity'].upper()} {alert['title']} ({alert['rule_name']})" for alert in payload["alerts"]] or ["- None attached"])
    lines.extend(["", "## Evidence"])
    lines.extend([f"- {item.get('title', 'Evidence')}: {item.get('value', '')}" for item in payload["evidence"]] or ["- None captured"])
    lines.extend(["", "## Timeline"])
    lines.extend([f"- {event['timestamp']} [{event['type']}] {event['content']}" for event in payload["timeline"]] or ["- No timeline events"])
    lines.extend(["", "## Recommended Next Steps"])
    lines.extend([f"- {step}" for step in payload["recommended_next_steps"]])
    return "\n".join(lines)


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
