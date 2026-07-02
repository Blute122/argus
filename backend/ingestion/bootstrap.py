"""First-run helpers for ingestion."""

from backend.config import settings
from backend.database.connection import SessionLocal
from backend.models.ingest_key import IngestKey, generate_key


def ensure_default_ingest_key() -> None:
    """Create a default ingest key on first run and print it once.

    The plaintext token is only recoverable at creation, so it is printed to the
    server log the single time it is generated. Admins can create more keys via
    POST /api/ingest/keys.
    """
    db = SessionLocal()
    try:
        if db.query(IngestKey).count() > 0:
            return
        token, prefix, key_hash = generate_key()
        db.add(IngestKey(name="default", tenant_id=settings.default_tenant,
                         key_prefix=prefix, key_hash=key_hash))
        db.commit()
        print("=" * 68)
        print("[Argus] Created default ingest key (shown once — store it now):")
        print(f"      {token}")
        print("      Use it as the X-Ingest-Key header for /api/ingest[/bulk].")
        print("=" * 68)
    finally:
        db.close()
