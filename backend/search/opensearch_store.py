"""OpenSearch-backed log store — the real SIEM search backend."""

import uuid
from types import SimpleNamespace

from backend.search.client import get_client, read_index_pattern, write_index_name
from backend.search.query_translator import build_query
from backend.search.schema import DOCUMENT_FIELDS, document_to_frontend, to_document
from backend.search.store import LogStore

# Attributes consumers (api/logs.py incident creation) expect on a log object.
_NS_FIELDS = (
    "id", "timestamp", "source", "source_ip", "destination_ip", "event_type",
    "event_id", "severity", "hostname", "username", "process_name",
    "command_line", "raw_log", "mitre_technique", "mitre_tactic", "dns_query",
    "url", "destination_port", "is_malicious",
)


def _hit_to_namespace(hit: dict) -> SimpleNamespace:
    src = hit.get("_source", {})
    data = {field: src.get(field) for field in _NS_FIELDS}
    data["id"] = hit.get("_id")
    return SimpleNamespace(**data)


class OpenSearchLogStore(LogStore):
    def __init__(self):
        self.client = get_client()

    def index_log(self, log_data: dict, ingest_source: str = "demo"):
        doc_id = uuid.uuid4().hex
        self.client.index(
            index=write_index_name(),
            id=doc_id,
            body=to_document(log_data, ingest_source),
        )
        return doc_id

    def search_logs(self, source=None, event_type=None, severity=None, limit=100, offset=0):
        must = []
        for field, value in (("source", source), ("event_type", event_type), ("severity", severity)):
            if value:
                must.append({"term": {field: {"value": value, "case_insensitive": True}}})
        query = {"bool": {"must": must}} if must else {"match_all": {}}
        resp = self.client.search(
            index=read_index_pattern(),
            body={"query": query, "sort": [{"@timestamp": "desc"}], "from": offset, "size": limit},
            ignore_unavailable=True,
        )
        return [document_to_frontend(h["_source"], h["_id"]) for h in resp["hits"]["hits"]]

    def hunt(self, query_str: str, limit: int = 500):
        resp = self.client.search(
            index=read_index_pattern(),
            body={"query": build_query(query_str), "sort": [{"@timestamp": "desc"}], "size": limit},
            ignore_unavailable=True,
        )
        return [document_to_frontend(h["_source"], h["_id"]) for h in resp["hits"]["hits"]]

    def get_logs_by_ids(self, ids: list):
        str_ids = list(dict.fromkeys(str(i) for i in ids))[:100]
        if not str_ids:
            return []
        resp = self.client.search(
            index=read_index_pattern(),
            body={"query": {"ids": {"values": str_ids}}, "size": len(str_ids)},
            ignore_unavailable=True,
        )
        return [_hit_to_namespace(h) for h in resp["hits"]["hits"]]

    def log_stats(self):
        resp = self.client.search(
            index=read_index_pattern(),
            body={
                "size": 0,
                "aggs": {
                    "by_source": {"terms": {"field": "source", "size": 50}},
                    "by_severity": {"terms": {"field": "severity", "size": 20}},
                },
            },
            ignore_unavailable=True,
        )
        total = resp["hits"]["total"]["value"]
        buckets = resp.get("aggregations", {})
        return {
            "total": total,
            "by_source": {b["key"]: b["doc_count"] for b in buckets.get("by_source", {}).get("buckets", [])},
            "by_severity": {b["key"]: b["doc_count"] for b in buckets.get("by_severity", {}).get("buckets", [])},
        }

    def dashboard_log_stats(self):
        resp = self.client.search(
            index=read_index_pattern(),
            body={
                "size": 0,
                "aggs": {
                    "by_source": {"terms": {"field": "source", "size": 50}},
                    "attackers": {
                        "filter": {"range": {"is_malicious": {"gte": 1}}},
                        "aggs": {"top_ips": {"terms": {"field": "source_ip", "size": 10}}},
                    },
                },
                "track_total_hits": True,
            },
            ignore_unavailable=True,
        )
        aggs = resp.get("aggregations", {})
        top = aggs.get("attackers", {}).get("top_ips", {}).get("buckets", [])
        return {
            "total_logs": resp["hits"]["total"]["value"],
            "source_distribution": {b["key"]: b["doc_count"] for b in aggs.get("by_source", {}).get("buckets", [])},
            "top_attackers": [{"ip": b["key"], "count": b["doc_count"]} for b in top],
        }
