"""The shared ingestion pipeline.

Every event — from the demo generator, syslog, HTTP bulk, or a tailed file —
flows through `ingest_event`:

    normalize -> tenant stamp -> enrich -> store -> detect -> persist alerts -> broadcast

Centralizing this here means all sources share the same detection and
broadcasting behavior, and the demo loop is no longer special-cased.
"""

from backend.config import settings
from backend.correlation_engine.rules import CorrelationEngine
from backend.database.connection import SessionLocal
from backend.detection.engine import detection_engine
from backend.ingestion.enrichment import enrich
from backend.models.alert import Alert
from backend.search import get_log_store
from backend.utils.records import coerce_datetime_fields
from backend.websocket.manager import manager

# Stateful multi-event correlation (e.g. the APT killchain) stays in the
# correlation engine; single-event detections are Sigma YAML rules run by the
# detection engine. Both see every event.
correlation_engine = CorrelationEngine()


async def ingest_event(log_data: dict, ingest_source: str = "demo", tenant_id: str | None = None) -> dict:
    """Ingest one normalized log event. Returns {log_id, alerts}."""
    log_data["tenant_id"] = tenant_id or log_data.get("tenant_id") or settings.default_tenant

    enrich(log_data)

    store = get_log_store()
    log_id = store.index_log(log_data, ingest_source=ingest_source)

    await manager.broadcast_log({**log_data, "id": log_id})

    generated = correlation_engine.process_log(log_data) + detection_engine.evaluate(log_data)
    if generated:
        db = SessionLocal()
        try:
            for alert_data in generated:
                entry = Alert(**{k: v for k, v in coerce_datetime_fields(alert_data).items() if hasattr(Alert, k)})
                db.add(entry)
                await manager.broadcast_alert(alert_data)
            db.commit()
        finally:
            db.close()

    return {"log_id": log_id, "alerts": len(generated)}
