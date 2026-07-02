"""Log store abstraction + factory.

The rest of the app talks to logs only through this interface, so the backing
store (OpenSearch vs relational fallback) is a config switch, not a code change.

Interface contract (all implementations):
  index_log(log_data, ingest_source) -> id
  search_logs(source, event_type, severity, limit, offset) -> list[frontend dict]
  hunt(query_str, limit) -> list[frontend dict]
  get_logs_by_ids(ids) -> list[object]   (attrs: id, hostname, source_ip, ...)
  log_stats() -> {total, by_source, by_severity}
  dashboard_log_stats() -> {total_logs, source_distribution, top_attackers}
"""

from backend.config import settings

_store = None


class LogStore:
    """Abstract log store interface."""

    def index_log(self, log_data: dict, ingest_source: str = "demo"):
        raise NotImplementedError

    def search_logs(self, source=None, event_type=None, severity=None, limit=100, offset=0) -> list[dict]:
        raise NotImplementedError

    def hunt(self, query_str: str, limit: int = 500) -> list[dict]:
        raise NotImplementedError

    def get_logs_by_ids(self, ids: list) -> list:
        raise NotImplementedError

    def log_stats(self) -> dict:
        raise NotImplementedError

    def dashboard_log_stats(self) -> dict:
        raise NotImplementedError


def get_log_store() -> LogStore:
    """Return the configured log store singleton."""
    global _store
    if _store is not None:
        return _store
    if settings.opensearch_enabled:
        from backend.search.opensearch_store import OpenSearchLogStore
        _store = OpenSearchLogStore()
    else:
        from backend.search.sql_store import SqlLogStore
        _store = SqlLogStore()
    return _store
