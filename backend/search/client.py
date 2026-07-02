"""OpenSearch client factory and index bootstrap."""

from datetime import datetime, timezone

from backend.config import settings
from backend.search.schema import INDEX_TEMPLATE

_client = None


def get_client():
    """Return a lazily-initialized OpenSearch client (or None if unavailable)."""
    global _client
    if _client is not None:
        return _client
    try:
        from opensearchpy import OpenSearch
    except ImportError as exc:  # opensearch-py not installed
        raise RuntimeError(
            "opensearch-py is not installed but OPENSEARCH_ENABLED=true. "
            "Run: pip install opensearch-py"
        ) from exc

    _client = OpenSearch(
        hosts=[settings.opensearch_url],
        http_auth=(settings.opensearch_user, settings.opensearch_password),
        use_ssl=settings.opensearch_url.startswith("https"),
        verify_certs=settings.opensearch_verify_certs,
        ssl_show_warn=False,
        timeout=30,
        max_retries=3,
        retry_on_timeout=True,
    )
    return _client


def write_index_name() -> str:
    """Time-based index to write to, e.g. logs-2026.07.02."""
    now = datetime.now(timezone.utc)
    if settings.opensearch_index_period == "month":
        suffix = now.strftime("%Y.%m")
    else:
        suffix = now.strftime("%Y.%m.%d")
    return f"{settings.opensearch_index_prefix}-{suffix}"


def read_index_pattern() -> str:
    """Wildcard covering all log indices for search/aggregation."""
    return f"{settings.opensearch_index_prefix}-*"


def bootstrap_indices():
    """Install the index template. Safe to call on every startup (idempotent)."""
    client = get_client()
    client.indices.put_index_template(name="logs-template", body=INDEX_TEMPLATE)


def ping() -> bool:
    try:
        return bool(get_client().ping())
    except Exception:
        return False
