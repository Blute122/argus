"""Load detection rule YAML files into rule objects."""

import os

import yaml

from backend.detection.sigma import SigmaRule
from backend.detection.threshold import ThresholdRule

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


def load_rules(rules_dir: str = RULES_DIR) -> list:
    """Parse every .yml/.yaml file in rules_dir into a rule object."""
    rules = []
    if not os.path.isdir(rules_dir):
        return rules
    for name in sorted(os.listdir(rules_dir)):
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(rules_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as exc:
            print(f"[DETECT] Failed to load {name}: {exc}")
            continue
        if not isinstance(data, dict):
            continue
        rule_id = data.get("id") or os.path.splitext(name)[0]
        try:
            if data.get("type") == "threshold":
                rules.append(ThresholdRule(data, rule_id, path))
            else:
                rules.append(SigmaRule(data, rule_id, path))
        except Exception as exc:  # malformed rule shouldn't crash the loader
            print(f"[DETECT] Skipping invalid rule {name}: {exc}")
    return rules
