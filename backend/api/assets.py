"""Asset inventory API endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, func
from sqlalchemy.orm import Session
from typing import Optional

from backend.api.auth import get_current_user
from backend.database.connection import get_db
from backend.models.alert import Alert
from backend.models.asset import Asset
from backend.models.vulnerability import Vulnerability
from backend.models.log import Log

router = APIRouter(prefix="/api/assets", tags=["Assets"])


class AssetCreate(BaseModel):
    hostname: str
    ip_address: str
    asset_type: str = "workstation"
    operating_system: Optional[str] = None
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    criticality: str = "medium"
    risk_score: int = 30
    status: str = "online"
    location: Optional[str] = None
    notes: Optional[str] = None


class AssetUpdate(BaseModel):
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    criticality: Optional[str] = None
    risk_score: Optional[int] = None
    status: Optional[str] = None
    notes: Optional[str] = None


class VulnerabilityCreate(BaseModel):
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    cvss_score: Optional[str] = None
    status: str = "open"


@router.get("/")
def list_assets(
    status: Optional[str] = None,
    criticality: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = Query(default=200, le=500),
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
):
    q = db.query(Asset).order_by(desc(Asset.risk_score), Asset.hostname)
    if status:
        q = q.filter(Asset.status == status)
    if criticality:
        q = q.filter(Asset.criticality == criticality)
    if query:
        like = f"%{query}%"
        q = q.filter((Asset.hostname.ilike(like)) | (Asset.ip_address.ilike(like)) | (Asset.owner.ilike(like)))
    return [_format_asset(asset, db) for asset in q.limit(limit).all()]


@router.post("/")
def create_asset(data: AssetCreate, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    if db.query(Asset).filter((Asset.hostname == data.hostname) | (Asset.ip_address == data.ip_address)).first():
        raise HTTPException(status_code=400, detail="Asset hostname or IP already exists")
    asset = Asset(**data.model_dump(), last_seen=datetime.now(timezone.utc))
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return _format_asset(asset, db)


@router.patch("/{asset_id}")
def update_asset(asset_id: int, data: AssetUpdate, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(asset, key, value)
    db.commit()
    db.refresh(asset)
    return _format_asset(asset, db)


@router.post("/{asset_id}/vulnerabilities")
def add_vulnerability(asset_id: int, data: VulnerabilityCreate, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    vuln = Vulnerability(**data.model_dump(), asset_id=asset_id)
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    
    return {
        "id": vuln.id,
        "cve_id": vuln.cve_id,
        "title": vuln.title,
        "severity": vuln.severity,
        "cvss_score": vuln.cvss_score,
        "status": vuln.status
    }


@router.get("/stats")
def asset_stats(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    total = db.query(func.count(Asset.id)).scalar() or 0
    by_status = dict(db.query(Asset.status, func.count(Asset.id)).group_by(Asset.status).all())
    by_criticality = dict(db.query(Asset.criticality, func.count(Asset.id)).group_by(Asset.criticality).all())
    high_risk = db.query(func.count(Asset.id)).filter(Asset.risk_score >= 70).scalar() or 0
    isolated = db.query(func.count(Asset.id)).filter(Asset.status == "isolated").scalar() or 0
    return {
        "total": total,
        "high_risk": high_risk,
        "isolated": isolated,
        "by_status": by_status,
        "by_criticality": by_criticality,
    }


@router.get("/{asset_id}/telemetry")
def asset_telemetry(asset_id: int, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    alerts = db.query(Alert).filter(
        (Alert.hostname == asset.hostname) | (Alert.source_ip == asset.ip_address) | (Alert.destination_ip == asset.ip_address)
    ).order_by(desc(Alert.timestamp)).limit(25).all()
    logs = db.query(Log).filter(
        (Log.hostname == asset.hostname) | (Log.source_ip == asset.ip_address) | (Log.destination_ip == asset.ip_address)
    ).order_by(desc(Log.timestamp)).limit(50).all()
    return {
        "asset": _format_asset(asset, db),
        "alerts": [{
            "id": alert.id,
            "timestamp": str(alert.timestamp),
            "title": alert.title,
            "severity": alert.severity,
            "status": alert.status,
            "mitre_technique": alert.mitre_technique,
            "rule_name": alert.rule_name,
        } for alert in alerts],
        "logs": [{
            "id": log.id,
            "timestamp": str(log.timestamp),
            "source": log.source,
            "event_type": log.event_type,
            "severity": log.severity,
            "raw_log": log.raw_log,
            "mitre_technique": log.mitre_technique,
        } for log in logs],
    }


def _format_asset(asset: Asset, db: Session):
    alert_count = db.query(func.count(Alert.id)).filter(
        (Alert.hostname == asset.hostname) | (Alert.source_ip == asset.ip_address) | (Alert.destination_ip == asset.ip_address)
    ).scalar() or 0
    log_count = db.query(func.count(Log.id)).filter(
        (Log.hostname == asset.hostname) | (Log.source_ip == asset.ip_address) | (Log.destination_ip == asset.ip_address)
    ).scalar() or 0
    
    vulns = db.query(Vulnerability).filter(Vulnerability.asset_id == asset.id).all()
    vuln_list = [{
        "id": v.id,
        "cve_id": v.cve_id,
        "title": v.title,
        "severity": v.severity,
        "cvss_score": v.cvss_score,
        "status": v.status
    } for v in vulns]

    return {
        "id": asset.id,
        "hostname": asset.hostname,
        "ip_address": asset.ip_address,
        "asset_type": asset.asset_type,
        "operating_system": asset.operating_system,
        "owner": asset.owner,
        "business_unit": asset.business_unit,
        "criticality": asset.criticality,
        "risk_score": asset.risk_score,
        "status": asset.status,
        "location": asset.location,
        "last_seen": str(asset.last_seen) if asset.last_seen else None,
        "notes": asset.notes,
        "alert_count": alert_count,
        "log_count": log_count,
        "vulnerabilities": vuln_list
    }