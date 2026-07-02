"""Parser interface + shared helpers.

A parser is a callable: `parse(raw) -> dict | None`, where `raw` is a str (a raw
log line) or a dict (already-structured event), and the return is a flat log
dict using the field names in `backend.search.schema.DOCUMENT_FIELDS` (None if
the input can't be parsed). Only `source`, `event_type` and `raw_log` are
required downstream; everything else is optional.
"""

from typing import Callable, Optional, Union

RawEvent = Union[str, dict, bytes]
Parser = Callable[[RawEvent], Optional[dict]]

# Fields we accept straight through from structured input (subset of DOCUMENT_FIELDS
# plus a couple of convenience aliases handled by callers).
PASSTHROUGH_FIELDS = {
    "tenant_id", "timestamp", "source", "source_ip", "destination_ip",
    "source_port", "destination_port", "protocol", "event_type", "event_id",
    "severity", "raw_log", "hostname", "username", "process_name", "process_id",
    "command_line", "file_path", "registry_key", "dns_query", "url",
    "user_agent", "http_method", "http_status", "bytes_sent", "bytes_received",
    "mitre_tactic", "mitre_technique", "mitre_technique_name", "geo_country",
    "geo_city", "confidence", "is_malicious",
}


def as_text(raw: RawEvent) -> str:
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return raw if isinstance(raw, str) else str(raw)
