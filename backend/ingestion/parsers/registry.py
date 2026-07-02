"""Parser registry + selection.

Choose a parser by an explicit `source_type` hint, or sniff the content when the
hint is "auto": JSON-looking payloads go to the json parser, everything else to
syslog (which itself falls back to a raw event).
"""

from backend.ingestion.parsers import json_passthrough, syslog
from backend.ingestion.parsers.base import RawEvent, as_text

_PARSERS = {
    "json": json_passthrough.parse,
    "syslog": syslog.parse,
}


def register(source_type: str, parser) -> None:
    """Register a custom parser under a source_type name."""
    _PARSERS[source_type] = parser


def _sniff(raw: RawEvent) -> str:
    if isinstance(raw, dict):
        return "json"
    text = as_text(raw).lstrip()
    if text[:1] in ("{", "["):
        return "json"
    return "syslog"


def parse(raw: RawEvent, source_type: str = "auto"):
    """Parse raw input into a normalized flat log dict (or None)."""
    if source_type == "auto" or source_type not in _PARSERS:
        source_type = _sniff(raw)
    return _PARSERS[source_type](raw)
