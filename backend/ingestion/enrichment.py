"""Event enrichment.

Runs cheap, in-memory normalization on every ingested event so downstream
detection and search see consistent fields regardless of source. Heavier
enrichers (GeoIP, threat-intel reputation, asset correlation) are intentionally
left as documented extension points rather than per-event DB/network calls —
wire them in when a data source is available.
"""

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def enrich(log_data: dict) -> dict:
    """Normalize a log dict in place and return it."""
    # Source is used for weighting/agg; keep it lowercased and present.
    source = log_data.get("source")
    if isinstance(source, str):
        log_data["source"] = source.lower()

    # Severity must be one of the known buckets.
    sev = log_data.get("severity")
    if sev not in _VALID_SEVERITIES:
        log_data["severity"] = "info"

    # is_malicious is an int flag (0 benign / 1 suspicious / 2 malicious).
    mal = log_data.get("is_malicious")
    if mal is None:
        log_data["is_malicious"] = 0
    else:
        try:
            log_data["is_malicious"] = int(mal)
        except (TypeError, ValueError):
            log_data["is_malicious"] = 0

    # --- Extension points (no-ops by default) --------------------------------
    # _enrich_geoip(log_data)         # requires a MaxMind GeoLite2 DB
    # _enrich_threat_intel(log_data)  # requires a reputation feed / API
    # _enrich_asset(log_data)         # correlate host/ip -> asset criticality
    return log_data
