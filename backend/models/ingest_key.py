"""API keys for authenticating log ingestion (agents / collectors)."""

import hashlib
import secrets

from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.sql import func

from backend.database.connection import Base


class IngestKey(Base):
    __tablename__ = "ingest_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(120), nullable=False)
    tenant_id = Column(String(64), default="default", index=True)
    key_prefix = Column(String(12), nullable=False)      # shown in UI, e.g. "ing_ab12cd"
    key_hash = Column(String(64), nullable=False, index=True, unique=True)  # sha256 hex
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)


def hash_key(token: str) -> str:
    """Fast hash for lookup. Ingest tokens are high-entropy, so sha256 is safe."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_key() -> tuple[str, str, str]:
    """Return (plaintext_token, key_prefix, key_hash). Plaintext is shown once."""
    token = "ing_" + secrets.token_urlsafe(32)
    return token, token[:12], hash_key(token)
