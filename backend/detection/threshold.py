"""Threshold (scheduled/aggregation) detection rules.

Runs a hunt query over a recent time window and fires when the number of
matching events for a given group (e.g. per source_ip) meets a count. This
replaces fragile in-memory counters (like the old brute-force rule) with a
real periodic search — and works on any log store via `store.hunt`.
"""

from datetime import datetime, timezone

from backend.mitre.mappings import get_technique
from backend.detection.sigma import _LEVEL_TO_SEVERITY, _technique_from_tags


class ThresholdRule:
    rule_type = "threshold"

    def __init__(self, data: dict, rule_id: str, path: str | None = None):
        self.id = str(data.get("id") or rule_id)
        self.title = data.get("title", self.id)
        self.description = data.get("description", "")
        self.level = str(data.get("level") or "high").lower()
        self.severity = _LEVEL_TO_SEVERITY.get(self.level, "high")
        self.tags = data.get("tags", []) or []
        self.recommended_action = data.get("recommended_action", "")
        self.path = path

        th = data.get("threshold", {}) or {}
        self.query = str(th.get("query", "*"))
        self.group_by = th.get("group_by")
        self.count = int(th.get("count", 5))
        self.window_minutes = int(th.get("window_minutes", 5))

        self.technique = _technique_from_tags(self.tags)
        info = get_technique(self.technique) if self.technique else None
        self.mitre_tactic = info["tactic_name"] if info else ""
        self.mitre_technique_name = info["name"] if info else ""

    def _windowed_query(self) -> str:
        window = f"earliest=-{self.window_minutes}m"
        base = self.query.strip()
        if not base or base == "*":
            return window
        return f"{base} {window}"

    def evaluate(self, store) -> list[dict]:
        """Return alert dicts for every group that meets the threshold."""
        events = store.hunt(self._windowed_query(), limit=5000)
        groups: dict = {}
        for event in events:
            key = event.get(self.group_by) if self.group_by else "_all"
            if key is None:
                continue
            groups.setdefault(key, []).append(event)

        alerts = []
        for key, matched in groups.items():
            if len(matched) >= self.count:
                alerts.append(self._alert(key, len(matched), matched[0]))
        return alerts

    def _alert(self, key, hits: int, sample: dict) -> dict:
        where = f"{self.group_by}={key}" if self.group_by else "environment"
        return {
            "title": self.title,
            "description": f"{self.description} ({hits} events for {where} in {self.window_minutes}m)",
            "severity": self.severity,
            "source_ip": key if self.group_by == "source_ip" else sample.get("source_ip"),
            "destination_ip": sample.get("destination_ip"),
            "rule_name": self.title,
            "hostname": sample.get("hostname"),
            "username": sample.get("username"),
            "event_count": hits,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.technique or "",
            "mitre_technique_name": self.mitre_technique_name,
            "recommended_action": self.recommended_action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
