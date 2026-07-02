"""Log storage/search layer.

Abstracts the log store behind a common interface so the application can run
against either OpenSearch (real SIEM backend) or the relational DB (zero-infra
fallback). Use `get_log_store()` to obtain the configured implementation.
"""

from backend.search.store import get_log_store

__all__ = ["get_log_store"]
