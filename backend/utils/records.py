"""Helpers for converting generated telemetry dictionaries into ORM records."""

from datetime import datetime


def coerce_datetime_fields(data: dict) -> dict:
    """Return a copy with ISO timestamp strings converted for SQLAlchemy DateTime columns."""
    normalized = dict(data)
    for field in ("timestamp", "first_seen", "last_seen", "started_at", "completed_at"):
        value = normalized.get(field)
        if isinstance(value, str):
            try:
                normalized[field] = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                normalized.pop(field, None)
    return normalized
