"""Detection engine (Phase 3).

Sigma-style YAML detection rules evaluated in two modes:
- streaming: per-event field matching in the ingestion pipeline (store-agnostic)
- scheduled: periodic threshold/aggregation queries via the log store

Rule content lives as YAML in `rules/`; enable/disable state and fire stats
live in the `detection_rules` metadata table.
"""

__all__ = ["detection_engine"]


def __getattr__(name):
    # Lazy re-export so submodules can be imported without pulling the whole
    # engine (and its DB/store deps) at package import time.
    if name == "detection_engine":
        from backend.detection.engine import detection_engine
        return detection_engine
    raise AttributeError(name)
