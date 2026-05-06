"""MITRE ATT&CK API endpoints."""
from fastapi import APIRouter, Depends
from backend.mitre.mappings import MITRE_TACTICS, MITRE_TECHNIQUES, get_technique, get_all_techniques
from backend.api.auth import get_current_user

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])


@router.get("/tactics")
def list_tactics(_user=Depends(get_current_user)):
    return [{"id": k, "name": v} for k, v in MITRE_TACTICS.items()]


@router.get("/techniques")
def list_techniques(_user=Depends(get_current_user)):
    return get_all_techniques()


@router.get("/techniques/{technique_id}")
def technique_detail(technique_id: str, _user=Depends(get_current_user)):
    t = get_technique(technique_id)
    if not t:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Technique not found")
    return {"id": technique_id, **t}
