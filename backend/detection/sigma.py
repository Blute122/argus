"""A pragmatic Sigma-subset rule model + matcher.

Supports the common Sigma constructs so real SigmaHQ rules can largely be
dropped in, while staying dependency-free and store-agnostic (it evaluates a
single event dict):

- named selections mapping `field[|modifier...]` -> value | [values]
- list value = OR; `|all` modifier = AND across the list
- modifiers: contains, startswith, endswith, re, gt, gte, lt, lte
- condition: boolean expression over selection names with and/or/not/parens,
  plus `all of them`, `1 of them`, `all of prefix*`, `1 of prefix*`

Fields map to our flat log schema (event_type, command_line, source_ip, ...).
"""

import re
from datetime import datetime, timezone

from backend.mitre.mappings import get_technique

_LEVEL_TO_SEVERITY = {
    "informational": "info", "info": "info", "low": "low",
    "medium": "medium", "high": "high", "critical": "critical",
}


def _technique_from_tags(tags):
    for tag in tags or []:
        low = str(tag).lower()
        if low.startswith("attack.t"):
            return low.split(".", 1)[1].upper()
    return None


class SigmaRule:
    rule_type = "streaming"

    def __init__(self, data: dict, rule_id: str, path: str | None = None):
        self.id = str(data.get("id") or rule_id)
        self.title = data.get("title", self.id)
        self.description = data.get("description", "")
        self.level = str(data.get("level") or "medium").lower()
        self.severity = _LEVEL_TO_SEVERITY.get(self.level, "medium")
        self.tags = data.get("tags", []) or []
        self.recommended_action = data.get("recommended_action", "")
        self.detection = data.get("detection", {}) or {}
        self.condition = str(self.detection.get("condition", "")).strip()
        self.path = path
        self.technique = _technique_from_tags(self.tags)
        info = get_technique(self.technique) if self.technique else None
        self.mitre_tactic = info["tactic_name"] if info else ""
        self.mitre_technique_name = info["name"] if info else ""

    # --- evaluation --------------------------------------------------------

    def _selection_names(self):
        return [k for k in self.detection if k not in ("condition", "timeframe")]

    def matches(self, event: dict) -> bool:
        if not self.condition:
            return False
        results = {name: _match_selection(self.detection[name], event) for name in self._selection_names()}
        try:
            return _eval_condition(self.condition, results)
        except Exception:
            return False

    def to_alert(self, event: dict) -> dict:
        return {
            "title": self.title,
            "description": self.description or f"{self.title} matched",
            "severity": self.severity,
            "source_ip": event.get("source_ip"),
            "destination_ip": event.get("destination_ip"),
            "rule_name": self.title,
            "hostname": event.get("hostname"),
            "username": event.get("username"),
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.technique or "",
            "mitre_technique_name": self.mitre_technique_name,
            "recommended_action": self.recommended_action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# --- selection / field matching -------------------------------------------

def _match_selection(sel, event: dict) -> bool:
    if isinstance(sel, list):  # list of maps -> OR
        return any(_match_selection(item, event) for item in sel)
    if not isinstance(sel, dict):
        return False
    for key, spec in sel.items():
        field, *mods = key.split("|")
        if not _match_field(event.get(field), spec, mods):
            return False
    return True


def _match_field(value, spec, mods) -> bool:
    require_all = "all" in mods
    compare = _comparator(mods)
    values = spec if isinstance(spec, list) else [spec]
    if require_all:
        return all(compare(value, target) for target in values)
    return any(compare(value, target) for target in values)


def _comparator(mods):
    for numeric in ("gt", "gte", "lt", "lte"):
        if numeric in mods:
            return lambda v, t, op=numeric: _num_cmp(v, t, op)
    if "contains" in mods:
        return lambda v, t: t is not None and str(t).lower() in str(v).lower() if v is not None else False
    if "startswith" in mods:
        return lambda v, t: v is not None and str(v).lower().startswith(str(t).lower())
    if "endswith" in mods:
        return lambda v, t: v is not None and str(v).lower().endswith(str(t).lower())
    if "re" in mods:
        return lambda v, t: v is not None and re.search(str(t), str(v), re.IGNORECASE) is not None
    return _equals


def _equals(v, t) -> bool:
    if v is None:
        return t is None
    if isinstance(t, bool):
        return bool(v) == t
    return str(v).lower() == str(t).lower()


def _num_cmp(v, t, op) -> bool:
    try:
        v, t = float(v), float(t)
    except (TypeError, ValueError):
        return False
    return {"gt": v > t, "gte": v >= t, "lt": v < t, "lte": v <= t}[op]


# --- condition expression --------------------------------------------------

_AGG_RE = re.compile(r"(?P<quant>all|\d+)\s+of\s+(?P<target>them|[\w*]+)", re.IGNORECASE)
_TOKEN_RE = re.compile(r"\(|\)|[A-Za-z0-9_.*\-]+")


def _eval_condition(condition: str, results: dict) -> bool:
    names = list(results.keys())

    def expand(m):
        quant, target = m.group("quant").lower(), m.group("target")
        if target.lower() == "them":
            chosen = names
        else:
            prefix = target.rstrip("*")
            chosen = [n for n in names if n.startswith(prefix)]
        if not chosen:
            return "False"
        joiner = " and " if quant == "all" else " or "
        return "(" + joiner.join(chosen) + ")"

    expanded = _AGG_RE.sub(expand, condition)
    return _boolean_eval(expanded, results)


def _boolean_eval(expr: str, results: dict) -> bool:
    tokens = _TOKEN_RE.findall(expr)
    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def advance():
        tok = peek()
        pos[0] += 1
        return tok

    def parse_or():
        value = parse_and()
        while (t := peek()) and t.lower() == "or":
            advance()
            value = parse_and() or value
        return value

    def parse_and():
        value = parse_not()
        while (t := peek()) and t.lower() == "and":
            advance()
            right = parse_not()
            value = value and right
        return value

    def parse_not():
        t = peek()
        if t and t.lower() == "not":
            advance()
            return not parse_not()
        return parse_atom()

    def parse_atom():
        t = advance()
        if t == "(":
            value = parse_or()
            if peek() == ")":
                advance()
            return value
        if t in ("True", "False"):
            return t == "True"
        return bool(results.get(t, False))

    return parse_or()
