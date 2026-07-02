"""Syslog parser (RFC 3164 "BSD" and RFC 5424).

Extracts priority (facility/severity), timestamp, hostname and the app/tag, and
keeps the full line in raw_log. Falls back to a plain-text event if the line
isn't well-formed syslog, so nothing is silently dropped.
"""

import re
from datetime import datetime, timezone

from backend.ingestion.parsers.base import RawEvent, as_text

# <PRI>VERSION? TIMESTAMP HOST APP...   (5424 has a version digit after PRI)
_PRI_RE = re.compile(r"^<(\d{1,3})>(\d)?\s*(.*)$", re.DOTALL)
_RFC3164_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$",
    re.DOTALL,
)
_RFC5424_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$",
    re.DOTALL,
)

# syslog severity number (PRI % 8) -> our severity bucket
_SEVERITY = {
    0: "critical", 1: "critical", 2: "critical", 3: "high",
    4: "medium", 5: "low", 6: "info", 7: "info",
}


def _severity_from_pri(pri: int) -> str:
    return _SEVERITY.get(pri % 8, "info")


def parse(raw: RawEvent):
    line = as_text(raw).strip()
    if not line:
        return None

    out = {"source": "syslog", "event_type": "syslog", "raw_log": line}

    m = _PRI_RE.match(line)
    remainder = line
    if m:
        pri, version, remainder = int(m.group(1)), m.group(2), m.group(3)
        out["severity"] = _severity_from_pri(pri)
        is_5424 = version is not None
    else:
        is_5424 = False

    if is_5424:
        sm = _RFC5424_RE.match(remainder)
        if sm:
            out["hostname"] = _none_dash(sm.group("host"))
            out["process_name"] = _none_dash(sm.group("app"))
            pid = sm.group("pid")
            if pid and pid.isdigit():
                out["process_id"] = int(pid)
            out["timestamp"] = _parse_5424_ts(sm.group("ts"))
            out["raw_log"] = sm.group("rest") or line
            return out

    bm = _RFC3164_RE.match(remainder)
    if bm:
        out["hostname"] = bm.group("host")
        rest = bm.group("rest")
        tag = rest.split(":", 1)[0].split("[", 1)[0].strip()
        if tag and len(tag) < 64:
            out["process_name"] = tag
        out["timestamp"] = _parse_3164_ts(bm.group("ts"))
        return out

    # Not structured syslog — keep it as a raw event.
    return out


def _none_dash(value: str):
    return None if value in ("-", "") else value


def _parse_5424_ts(value: str):
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def _parse_3164_ts(value: str):
    # RFC 3164 has no year; assume current year.
    try:
        dt = datetime.strptime(value, "%b %d %H:%M:%S")
        dt = dt.replace(year=datetime.now(timezone.utc).year, tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()
