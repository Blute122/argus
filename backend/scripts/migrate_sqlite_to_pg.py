"""One-off migration: copy relational metadata from SQLite to Postgres.

Copies users, incidents, incident_notes, alerts, assets, vulnerabilities,
hunt_queries and attack_simulations. The high-volume `logs` table is NOT copied
by default (it is ephemeral demo data); pass --include-logs to reindex existing
SQLite logs into OpenSearch instead.

Usage:
  python -m backend.scripts.migrate_sqlite_to_pg \
      --source sqlite:///./soc_simulator.db \
      --target postgresql+psycopg2://soc:soc@localhost:5432/soc

  # also push old logs into OpenSearch (requires OPENSEARCH_ENABLED=true):
  python -m backend.scripts.migrate_sqlite_to_pg --include-logs
"""

import argparse

from sqlalchemy import create_engine, insert, select

# Importing the models registers their tables on Base.metadata.
from backend.database.connection import Base
from backend.models import (  # noqa: F401
    user, log, alert, incident, hunt_query, attack_simulation, asset,
)

# Tables copied relationally (order matters for FKs; sorted_tables handles it).
LOGS_TABLE = "logs"


def copy_metadata(source_url: str, target_url: str) -> None:
    src = create_engine(source_url)
    dst = create_engine(target_url)

    # Create the schema on the target.
    Base.metadata.create_all(bind=dst)

    with src.connect() as sconn, dst.begin() as dconn:
        for table in Base.metadata.sorted_tables:
            if table.name == LOGS_TABLE:
                continue
            rows = [dict(r._mapping) for r in sconn.execute(select(table))]
            if not rows:
                print(f"  {table.name}: 0 rows")
                continue
            dconn.execute(insert(table), rows)
            print(f"  {table.name}: {len(rows)} rows copied")
    print("Metadata migration complete.")


def reindex_logs(source_url: str) -> None:
    from backend.search import get_log_store
    from backend.search.client import bootstrap_indices

    bootstrap_indices()
    store = get_log_store()

    src = create_engine(source_url)
    logs_table = Base.metadata.tables[LOGS_TABLE]
    count = 0
    with src.connect() as sconn:
        for row in sconn.execute(select(logs_table)):
            data = dict(row._mapping)
            data.pop("id", None)
            store.index_log(data, ingest_source="migrated")
            count += 1
    print(f"Reindexed {count} logs into OpenSearch.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate SOC metadata SQLite -> Postgres")
    parser.add_argument("--source", default="sqlite:///./soc_simulator.db")
    parser.add_argument("--target", default="postgresql+psycopg2://soc:soc@localhost:5432/soc")
    parser.add_argument("--include-logs", action="store_true",
                        help="Also reindex SQLite logs into OpenSearch (needs OPENSEARCH_ENABLED=true).")
    args = parser.parse_args()

    print(f"Copying metadata: {args.source} -> {args.target}")
    copy_metadata(args.source, args.target)

    if args.include_logs:
        reindex_logs(args.source)


if __name__ == "__main__":
    main()
