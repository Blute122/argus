"""Parser for already-structured JSON events (agents, Beats, Vector, curl).

Accepts a dict or a JSON string. Recognized fields are passed through; a few
common ECS-style aliases are mapped to our flat schema so external shippers work
without custom config.
"""

import json

from backend.ingestion.parsers.base import PASSTHROUGH_FIELDS, RawEvent, as_text

# Common ECS / agent field names -> our flat field names.
ALIASES = {
    "@timestamp": "timestamp",
    "host": "hostname",
    "host.name": "hostname",
    "message": "raw_log",
    "user": "username",
    "user.name": "username",
    "src_ip": "source_ip",
    "source.ip": "source_ip",
    "dst_ip": "destination_ip",
    "destination.ip": "destination_ip",
    "destination.port": "destination_port",
    "process.name": "process_name",
    "process.command_line": "command_line",
    "dns.question.name": "dns_query",
    "url.full": "url",
}


def parse(raw: RawEvent):
    if isinstance(raw, dict):
        data = raw
    else:
        text = as_text(raw).strip()
        if not text or text[0] not in "{[":
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None

    out = {}
    for key, value in data.items():
        target = ALIASES.get(key, key)
        if target in PASSTHROUGH_FIELDS:
            out[target] = value

    # Sensible defaults so the event is usable downstream.
    out.setdefault("source", data.get("source") or "json")
    out.setdefault("event_type", data.get("event_type") or "generic")
    out.setdefault("raw_log", as_text(raw) if not isinstance(raw, dict) else json.dumps(data))
    return out
