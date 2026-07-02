"""Translate the SPL/KQL-like hunt syntax into an OpenSearch query DSL.

Reuses the same tokenizer semantics, field aliases and time parsing as the
legacy `backend/utils/query_parser.py` (which targets SQLAlchemy), but emits a
`bool` query instead of a SQL filter. Keeping one syntax means the frontend
hunt UI is unchanged.

Supported:
  source=windows AND eventid=4625
  process_name=powershell.exe OR command_line=*encoded*
  source=network NOT severity=info
  "C2 beacon"                      (free-text over message/command_line)
  earliest=-24h latest=2026-06-20T18:00:00
"""

import shlex
from datetime import datetime, timedelta, timezone

from backend.search.schema import IP_FIELDS, NUMERIC_FIELDS, TEXT_FIELDS

FIELD_ALIASES = {
    "eventid": "event_id",
    "host": "hostname",
    "user": "username",
    "src": "source_ip",
    "src_ip": "source_ip",
    "dst": "destination_ip",
    "dst_ip": "destination_ip",
    "dest_ip": "destination_ip",
    "dest_port": "destination_port",
    "port": "destination_port",
    "process": "process_name",
    "cmd": "command_line",
    "dns": "dns_query",
    "raw": "raw_log",
}

# Free-text search targets when a bare term (no field=value) is supplied.
FREE_TEXT_FIELDS = ["raw_log", "command_line", "message"]

_MATCH_ALL = {"match_all": {}}


def build_query(query_str: str) -> dict:
    """Return an OpenSearch query DSL dict for the given hunt string."""
    tokens = _tokenize(query_str)
    if not tokens or tokens == ["*"]:
        return _MATCH_ALL

    clauses: list[dict] = []
    operators: list[str] = []
    negate_next = False

    for token in tokens:
        upper = token.upper()
        if upper in {"AND", "OR"}:
            operators.append(upper)
            continue
        if upper == "NOT":
            negate_next = True
            continue
        clause = _token_to_clause(token)
        if negate_next:
            clause = {"bool": {"must_not": [clause]}}
            negate_next = False
        clauses.append(clause)

    if not clauses:
        return _MATCH_ALL
    if len(clauses) == 1:
        return clauses[0]

    # If every operator is OR, use should; otherwise treat as AND (must). This
    # mirrors the left-to-right precedence of the legacy SQL parser closely
    # enough for practical hunts.
    if operators and all(op == "OR" for op in operators):
        return {"bool": {"should": clauses, "minimum_should_match": 1}}
    return {"bool": {"must": clauses}}


def _tokenize(query_str: str) -> list[str]:
    if not query_str or query_str.strip() == "*":
        return ["*"]
    try:
        return shlex.split(query_str)
    except ValueError:
        return query_str.split()


def _token_to_clause(token: str) -> dict:
    for operator in (">=", "<=", ">", "<", "="):
        if operator in token:
            field, value = token.split(operator, 1)
            return _field_clause(field.strip(), operator, value.strip().strip("'\""))
    # Bare term -> free-text search across message-like fields.
    return {"multi_match": {"query": token, "fields": FREE_TEXT_FIELDS, "type": "phrase"}}


def _field_clause(field: str, operator: str, value: str) -> dict:
    field = FIELD_ALIASES.get(field.lower(), field.lower())

    if field in {"earliest", "latest"}:
        parsed = _parse_time(value)
        if not parsed:
            return _MATCH_ALL
        bound = "gte" if field == "earliest" else "lte"
        return {"range": {"@timestamp": {bound: parsed.isoformat()}}}

    if field in NUMERIC_FIELDS:
        try:
            numeric = int(value)
        except ValueError:
            return {"wildcard": {field: {"value": value, "case_insensitive": True}}}
        op_map = {">=": "gte", "<=": "lte", ">": "gt", "<": "lt"}
        if operator in op_map:
            return {"range": {field: {op_map[operator]: numeric}}}
        return {"term": {field: numeric}}

    # Non-equality comparisons on non-numeric fields are meaningless; ignore.
    if operator != "=":
        return _MATCH_ALL

    # Choose the concrete field name to match on (text fields use .keyword).
    target = f"{field}.keyword" if field in TEXT_FIELDS else field

    if "*" in value or "?" in value:
        # IP type does not support wildcard; fall back to matching the raw log.
        if field in IP_FIELDS:
            return {"wildcard": {"raw_log.keyword": {"value": f"*{value}*", "case_insensitive": True}}}
        return {"wildcard": {target: {"value": value, "case_insensitive": True}}}

    if field in IP_FIELDS:
        return {"term": {field: value}}

    # Case-insensitive exact match on keyword-like fields.
    return {"term": {target: {"value": value, "case_insensitive": True}}}


def _parse_time(value: str):
    now = datetime.now(timezone.utc)
    if value.startswith("-") and len(value) > 2:
        unit = value[-1].lower()
        try:
            amount = int(value[1:-1])
        except ValueError:
            return None
        if unit == "m":
            return now - timedelta(minutes=amount)
        if unit == "h":
            return now - timedelta(hours=amount)
        if unit == "d":
            return now - timedelta(days=amount)
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
