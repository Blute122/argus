"""Normalized log document schema, index template, and (de)serializers.

For Phase 1 the OpenSearch document keeps the existing flat field names (the
same ones the `Log` ORM model and the React frontend already use), typed
correctly via an index template. This makes the query translator map 1:1 with
the legacy SPL parser and keeps the frontend serializer trivial. Fully-nested
ECS aliasing is layered in Phase 2 when external agents (Beats/Vector) feed in.
"""

from datetime import datetime, timezone

# Fields exposed to the React frontend (mirrors the legacy `_fmt_log`).
FRONTEND_FIELDS = (
    "source", "source_ip", "destination_ip", "event_type", "event_id",
    "severity", "hostname", "username", "process_name", "command_line",
    "raw_log", "mitre_tactic", "mitre_technique", "dns_query",
    "destination_port", "is_malicious",
)

# All fields we persist for a log document (superset of frontend fields).
DOCUMENT_FIELDS = (
    "tenant_id",
    "timestamp", "source", "source_ip", "destination_ip", "source_port",
    "destination_port", "protocol", "event_type", "event_id", "severity",
    "raw_log", "hostname", "username", "process_name", "process_id",
    "command_line", "file_path", "registry_key", "dns_query", "url",
    "user_agent", "http_method", "http_status", "bytes_sent", "bytes_received",
    "mitre_tactic", "mitre_technique", "mitre_technique_name", "geo_country",
    "geo_city", "confidence", "is_malicious",
)

# OpenSearch index template: pins types so aggregations, term filters, ip
# queries and full-text search behave correctly.
_KEYWORD = {"type": "keyword", "ignore_above": 1024}
_TEXT_KW = {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 2048}}}

INDEX_TEMPLATE = {
    "index_patterns": ["logs-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.refresh_interval": "1s",
        },
        "mappings": {
            "dynamic": False,
            "properties": {
                "@timestamp": {"type": "date"},
                "timestamp": {"type": "date"},
                "tenant_id": _KEYWORD,
                "ingest_source": _KEYWORD,
                "source": _KEYWORD,
                "source_ip": {"type": "ip", "ignore_malformed": True},
                "destination_ip": {"type": "ip", "ignore_malformed": True},
                "source_port": {"type": "long"},
                "destination_port": {"type": "long"},
                "protocol": _KEYWORD,
                "event_type": _KEYWORD,
                "event_id": _KEYWORD,
                "severity": _KEYWORD,
                "raw_log": _TEXT_KW,
                "hostname": _KEYWORD,
                "username": _KEYWORD,
                "process_name": _KEYWORD,
                "process_id": {"type": "long"},
                "command_line": _TEXT_KW,
                "file_path": _TEXT_KW,
                "registry_key": _TEXT_KW,
                "dns_query": _KEYWORD,
                "url": _TEXT_KW,
                "user_agent": _TEXT_KW,
                "http_method": _KEYWORD,
                "http_status": {"type": "long"},
                "bytes_sent": {"type": "long"},
                "bytes_received": {"type": "long"},
                "mitre_tactic": _KEYWORD,
                "mitre_technique": _KEYWORD,
                "mitre_technique_name": _KEYWORD,
                "geo_country": _KEYWORD,
                "geo_city": _KEYWORD,
                "confidence": {"type": "float"},
                "is_malicious": {"type": "integer"},
            },
        },
    },
}

# Fields that are numeric in the index (used by the query translator).
NUMERIC_FIELDS = {
    "source_port", "destination_port", "process_id", "http_status",
    "bytes_sent", "bytes_received", "is_malicious", "confidence",
}
# Text fields (analyzed). Term/wildcard queries must target the `.keyword` subfield.
TEXT_FIELDS = {"raw_log", "command_line", "file_path", "registry_key", "url", "user_agent"}
IP_FIELDS = {"source_ip", "destination_ip"}


def _parse_ts(value):
    """Coerce a timestamp (ISO string or datetime) to an aware UTC datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def to_document(log_data: dict, ingest_source: str = "demo") -> dict:
    """Build an OpenSearch document from a flat generator/parser log dict."""
    doc = {field: log_data.get(field) for field in DOCUMENT_FIELDS if log_data.get(field) is not None}
    ts = _parse_ts(log_data.get("timestamp")) or datetime.now(timezone.utc)
    iso = ts.isoformat()
    doc["timestamp"] = iso
    doc["@timestamp"] = iso
    doc["ingest_source"] = ingest_source
    doc.setdefault("tenant_id", log_data.get("tenant_id") or "default")
    return doc


def document_to_frontend(source: dict, doc_id) -> dict:
    """Flatten an OpenSearch _source hit into the JSON shape the frontend expects."""
    out = {"id": doc_id, "timestamp": source.get("timestamp") or source.get("@timestamp")}
    for field in FRONTEND_FIELDS:
        out[field] = source.get(field)
    return out


def orm_log_to_frontend(log) -> dict:
    """Flatten an ORM Log row into the frontend JSON shape (legacy fallback path)."""
    out = {"id": log.id, "timestamp": str(log.timestamp) if log.timestamp is not None else None}
    for field in FRONTEND_FIELDS:
        out[field] = getattr(log, field, None)
    return out
