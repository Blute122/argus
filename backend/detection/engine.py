"""Detection engine singleton.

Loads YAML rules, syncs their metadata into the `detection_rules` table
(preserving enable/disable + stats across restarts), evaluates streaming rules
against each event, and exposes threshold rules to the scheduler.
"""

import json
from datetime import datetime, timezone

from backend.database.connection import SessionLocal
from backend.detection.loader import load_rules
from backend.models.detection_rule import DetectionRule


class DetectionEngine:
    def __init__(self):
        self._streaming = []
        self._threshold = []
        self._enabled: dict[str, bool] = {}
        self._loaded = False

    # --- lifecycle ---------------------------------------------------------

    def load(self):
        rules = load_rules()
        self._streaming = [r for r in rules if r.rule_type == "streaming"]
        self._threshold = [r for r in rules if r.rule_type == "threshold"]
        self._sync_db(rules)
        self._loaded = True
        print(f"[DETECT] Loaded {len(self._streaming)} streaming + {len(self._threshold)} threshold rules")

    def _sync_db(self, rules):
        db = SessionLocal()
        try:
            for rule in rules:
                row = db.get(DetectionRule, rule.id)
                technique = getattr(rule, "technique", None)
                if row is None:
                    db.add(DetectionRule(
                        id=rule.id, title=rule.title, description=rule.description,
                        rule_type=rule.rule_type, severity=rule.severity,
                        mitre_technique=technique, tags=json.dumps(rule.tags),
                        source="builtin", enabled=True,
                    ))
                    self._enabled[rule.id] = True
                else:
                    # Refresh metadata from YAML, preserve enabled + stats.
                    row.title = rule.title
                    row.description = rule.description
                    row.rule_type = rule.rule_type
                    row.severity = rule.severity
                    row.mitre_technique = technique
                    row.tags = json.dumps(rule.tags)
                    self._enabled[rule.id] = bool(row.enabled)
            db.commit()
        finally:
            db.close()

    # --- evaluation --------------------------------------------------------

    def evaluate(self, event: dict) -> list[dict]:
        """Run enabled streaming rules against one event; return alert dicts."""
        if not self._loaded:
            return []
        alerts, fired = [], []
        for rule in self._streaming:
            if not self._enabled.get(rule.id, True):
                continue
            try:
                if rule.matches(event):
                    alerts.append(rule.to_alert(event))
                    fired.append(rule.id)
            except Exception:
                pass
        if fired:
            self.record_fires(fired)
        return alerts

    def active_threshold_rules(self):
        return [r for r in self._threshold if self._enabled.get(r.id, True)]

    # --- state / stats -----------------------------------------------------

    def set_enabled(self, rule_id: str, enabled: bool) -> bool:
        db = SessionLocal()
        try:
            row = db.get(DetectionRule, rule_id)
            if row is None:
                return False
            row.enabled = enabled
            db.commit()
            self._enabled[rule_id] = enabled
            return True
        finally:
            db.close()

    def record_fires(self, rule_ids, increment: int = 1):
        now = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            for rule_id in rule_ids:
                row = db.get(DetectionRule, rule_id)
                if row:
                    row.match_count = (row.match_count or 0) + increment
                    row.last_fired_at = now
            db.commit()
        finally:
            db.close()

    def get_rule(self, rule_id: str):
        for rule in self._streaming + self._threshold:
            if rule.id == rule_id:
                return rule
        return None


detection_engine = DetectionEngine()
