"""
Database connection and session management.
Supports SQLite (default) and PostgreSQL (upgrade path).
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import StaticPool

from backend.config import settings

DATABASE_URL = settings.database_url

# SQLite-specific: check_same_thread=False for FastAPI async
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False, "timeout": 15},
        poolclass=StaticPool,
        echo=False,
    )

    from sqlalchemy import event
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()
else:
    # PostgreSQL or other databases
    engine = create_engine(DATABASE_URL, echo=False)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Dependency for FastAPI route injection."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables on startup, then apply additive column migrations."""
    from backend.models import user, log, alert, incident, hunt_query, attack_simulation, asset, ingest_key, detection_rule  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _apply_additive_migrations()


# Lightweight additive migrations for existing DBs (no Alembic needed for
# add-column changes). Each entry: table -> {column: DDL type + default}.
_ADDITIVE_COLUMNS = {
    "logs": {"tenant_id": "VARCHAR(64) DEFAULT 'default'"},
}


def _apply_additive_migrations():
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    for table, columns in _ADDITIVE_COLUMNS.items():
        if table not in existing_tables:
            continue
        present = {c["name"] for c in inspector.get_columns(table)}
        for column, ddl in columns.items():
            if column in present:
                continue
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
                conn.execute(text(f"CREATE INDEX IF NOT EXISTS ix_{table}_{column} ON {table} ({column})"))
