"""Relational (SQLite/Postgres) log store — zero-infra fallback.

Preserves the exact legacy behavior: logs in the `logs` table, hunts via the
SQLAlchemy query parser, aggregations via GROUP BY. Used when
OPENSEARCH_ENABLED is false so the app runs without Docker/OpenSearch.
"""

from sqlalchemy import desc, func

from backend.database.connection import SessionLocal
from backend.models.log import Log
from backend.search.schema import orm_log_to_frontend
from backend.search.store import LogStore
from backend.utils.query_parser import build_filter
from backend.utils.records import coerce_datetime_fields


class SqlLogStore(LogStore):
    def index_log(self, log_data: dict, ingest_source: str = "demo"):
        db = SessionLocal()
        try:
            entry = Log(**{k: v for k, v in coerce_datetime_fields(log_data).items() if hasattr(Log, k)})
            db.add(entry)
            db.commit()
            db.refresh(entry)
            return entry.id
        finally:
            db.close()

    def search_logs(self, source=None, event_type=None, severity=None, limit=100, offset=0):
        db = SessionLocal()
        try:
            q = db.query(Log).order_by(desc(Log.timestamp))
            if source:
                q = q.filter(Log.source == source)
            if event_type:
                q = q.filter(Log.event_type == event_type)
            if severity:
                q = q.filter(Log.severity == severity)
            rows = q.offset(offset).limit(limit).all()
            return [orm_log_to_frontend(r) for r in rows]
        finally:
            db.close()

    def hunt(self, query_str: str, limit: int = 500):
        db = SessionLocal()
        try:
            rows = (
                db.query(Log)
                .filter(build_filter(query_str, Log))
                .order_by(desc(Log.timestamp))
                .limit(limit)
                .all()
            )
            return [orm_log_to_frontend(r) for r in rows]
        finally:
            db.close()

    def get_logs_by_ids(self, ids: list):
        int_ids = []
        for value in ids:
            try:
                int_ids.append(int(value))
            except (TypeError, ValueError):
                continue
        int_ids = list(dict.fromkeys(int_ids))[:100]
        if not int_ids:
            return []
        db = SessionLocal()
        try:
            return db.query(Log).filter(Log.id.in_(int_ids)).order_by(desc(Log.timestamp)).all()
        finally:
            db.close()

    def log_stats(self):
        db = SessionLocal()
        try:
            total = db.query(func.count(Log.id)).scalar() or 0
            by_source = dict(db.query(Log.source, func.count(Log.id)).group_by(Log.source).all())
            by_severity = dict(db.query(Log.severity, func.count(Log.id)).group_by(Log.severity).all())
            return {"total": total, "by_source": by_source, "by_severity": by_severity}
        finally:
            db.close()

    def dashboard_log_stats(self):
        db = SessionLocal()
        try:
            total_logs = db.query(func.count(Log.id)).scalar() or 0
            source_dist = dict(db.query(Log.source, func.count(Log.id)).group_by(Log.source).all())
            top = (
                db.query(Log.source_ip, func.count(Log.id))
                .filter(Log.is_malicious >= 1, Log.source_ip.isnot(None))
                .group_by(Log.source_ip)
                .order_by(func.count(Log.id).desc())
                .limit(10)
                .all()
            )
            return {
                "total_logs": total_logs,
                "source_distribution": source_dist,
                "top_attackers": [{"ip": ip, "count": cnt} for ip, cnt in top if ip],
            }
        finally:
            db.close()
