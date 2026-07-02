"""HTTP ingestion endpoints.

  POST /api/ingest        - one event (JSON object or a raw log line)
  POST /api/ingest/bulk   - NDJSON: one JSON object or raw line per line
  POST /api/ingest/keys   - (admin) create an ingest API key
  GET  /api/ingest/keys   - (admin) list ingest API keys

Agents/collectors authenticate with an ingest key via the `X-Ingest-Key`
header. The key maps to a tenant, which is stamped on every event it submits.
"""

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.api.auth import require_roles
from backend.database.connection import get_db
from backend.ingestion.parsers import parse as parse_raw
from backend.ingestion.pipeline import ingest_event
from backend.models.ingest_key import IngestKey, generate_key, hash_key

router = APIRouter(prefix="/api/ingest", tags=["Ingestion"])


def require_ingest_key(
    x_ingest_key: str = Header(default=None, alias="X-Ingest-Key"),
    db: Session = Depends(get_db),
) -> str:
    """Validate the ingest key and return its tenant_id."""
    if not x_ingest_key:
        raise HTTPException(status_code=401, detail="Missing X-Ingest-Key header")
    key = (
        db.query(IngestKey)
        .filter(IngestKey.key_hash == hash_key(x_ingest_key), IngestKey.enabled.is_(True))
        .first()
    )
    if not key:
        raise HTTPException(status_code=401, detail="Invalid or disabled ingest key")
    return key.tenant_id


async def _ingest_one(raw, source_type: str, tenant_id: str) -> bool:
    parsed = parse_raw(raw, source_type=source_type)
    if not parsed:
        return False
    await ingest_event(parsed, ingest_source="http", tenant_id=tenant_id)
    return True


@router.post("")
async def ingest_single(
    request: Request,
    source_type: str = "auto",
    tenant_id: str = Depends(require_ingest_key),
):
    body = await request.body()
    raw = body.decode("utf-8", errors="replace").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty body")
    ok = await _ingest_one(raw, source_type, tenant_id)
    if not ok:
        raise HTTPException(status_code=422, detail="Could not parse event")
    return {"ingested": 1}


@router.post("/bulk")
async def ingest_bulk(
    request: Request,
    source_type: str = "auto",
    tenant_id: str = Depends(require_ingest_key),
):
    body = await request.body()
    text = body.decode("utf-8", errors="replace")
    ingested = 0
    skipped = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if await _ingest_one(line, source_type, tenant_id):
            ingested += 1
        else:
            skipped += 1
    return {"ingested": ingested, "skipped": skipped}


# --- Key management (admin) --------------------------------------------------

class IngestKeyCreate(BaseModel):
    name: str
    tenant_id: str = "default"


@router.post("/keys")
def create_ingest_key(
    data: IngestKeyCreate,
    db: Session = Depends(get_db),
    _admin=Depends(require_roles(["admin"])),
):
    token, prefix, key_hash = generate_key()
    key = IngestKey(name=data.name, tenant_id=data.tenant_id, key_prefix=prefix, key_hash=key_hash)
    db.add(key)
    db.commit()
    db.refresh(key)
    # Plaintext token is returned exactly once.
    return {"id": key.id, "name": key.name, "tenant_id": key.tenant_id, "token": token,
            "note": "Store this token now; it cannot be retrieved again."}


@router.get("/keys")
def list_ingest_keys(
    db: Session = Depends(get_db),
    _admin=Depends(require_roles(["admin"])),
):
    keys = db.query(IngestKey).order_by(IngestKey.created_at.desc()).all()
    return [{"id": k.id, "name": k.name, "tenant_id": k.tenant_id, "key_prefix": k.key_prefix,
             "enabled": k.enabled, "created_at": str(k.created_at),
             "last_used_at": str(k.last_used_at) if k.last_used_at else None} for k in keys]
