"""Small SPL/KQL-like parser for safe log hunting filters."""

import shlex
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, cast, not_, or_
from sqlalchemy.sql.expression import true
from sqlalchemy.types import String


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
}


NUMERIC_FIELDS = {"destination_port", "source_port", "process_id", "bytes_sent", "bytes_received", "is_malicious"}


def build_filter(query_str: str, model):
    """Parse a practical hunt query into a SQLAlchemy filter.

    Supported examples:
    - source=windows AND eventid=4625
    - process_name=powershell.exe OR command_line=*encoded*
    - source=network NOT severity=info
    - raw contains terms via quoted/free text: "C2 beacon"
    - time filters: earliest=-24h latest=2026-06-20T18:00:00
    """
    tokens = _tokenize(query_str)
    if not tokens or tokens == ["*"]:
        return true()

    clauses = []
    operators = []
    negate_next = False

    for token in tokens:
        upper = token.upper()
        if upper in {"AND", "OR"}:
            operators.append(upper)
            continue
        if upper == "NOT":
            negate_next = True
            continue

        clause = _token_to_clause(token, model)
        if negate_next:
            clause = not_(clause)
            negate_next = False
        clauses.append(clause)

    if not clauses:
        return true()

    expression = clauses[0]
    for index, clause in enumerate(clauses[1:]):
        op = operators[index] if index < len(operators) else "AND"
        expression = or_(expression, clause) if op == "OR" else and_(expression, clause)
    return expression


def _tokenize(query_str: str) -> list[str]:
    if not query_str or query_str.strip() == "*":
        return ["*"]
    try:
        return shlex.split(query_str)
    except ValueError:
        return query_str.split()


def _token_to_clause(token: str, model):
    for operator in (">=", "<=", ">", "<", "="):
        if operator in token:
            field, value = token.split(operator, 1)
            return _field_clause(field.strip(), operator, value.strip().strip("'\""), model)
    return model.raw_log.ilike(f"%{token.replace('*', '%')}%")


def _field_clause(field: str, operator: str, value: str, model):
    field = FIELD_ALIASES.get(field.lower(), field.lower())

    if field in {"earliest", "latest"}:
        parsed = _parse_time(value)
        if not parsed:
            return true()
        return model.timestamp >= parsed if field == "earliest" else model.timestamp <= parsed

    if not hasattr(model, field):
        return model.raw_log.ilike(f"%{field}{operator}{value}%")

    column = getattr(model, field)
    if field in NUMERIC_FIELDS:
        try:
            numeric = int(value)
        except ValueError:
            return cast(column, String).ilike(value.replace("*", "%"))
        if operator == ">=":
            return column >= numeric
        if operator == "<=":
            return column <= numeric
        if operator == ">":
            return column > numeric
        if operator == "<":
            return column < numeric
        return column == numeric

    if operator != "=":
        return cast(column, String).op(operator)(value)

    if "*" in value:
        return cast(column, String).ilike(value.replace("*", "%"))
    return cast(column, String).ilike(value)


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
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
