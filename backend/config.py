"""Central application configuration (pydantic-settings).

Replaces scattered os.getenv() calls. Values are read from environment
variables or a local .env file. See .env.example for documentation.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Relational metadata store (users, incidents, alerts, assets, hunts) ---
    # SQLite by default so the app runs with zero infra; Postgres in Docker.
    database_url: str = "sqlite:///./soc_simulator.db"

    # --- Log store (OpenSearch) ---
    # When disabled, logs fall back to the relational store (SQLite/Postgres),
    # which keeps the app fully runnable without Docker/OpenSearch.
    opensearch_enabled: bool = False
    opensearch_url: str = "https://localhost:9200"
    opensearch_user: str = "admin"
    opensearch_password: str = "admin"
    opensearch_verify_certs: bool = False
    opensearch_index_prefix: str = "logs"
    # Roll indices by this granularity: "day" -> logs-YYYY.MM.DD, "month" -> logs-YYYY.MM
    opensearch_index_period: str = "day"

    # --- Data generation ---
    # Keep the synthetic generator running (training/demo/load). Set false in
    # production so only real ingested logs appear.
    demo_mode: bool = True

    # --- Tenancy ---
    # Single-org self-host uses one tenant. Carried on every log as a cheap
    # hedge that keeps a future multi-tenant/hosted tier possible.
    default_tenant: str = "default"

    # --- Ingestion (Phase 2) ---
    # HTTP bulk ingest endpoint (/api/ingest, /api/ingest/bulk).
    ingest_enabled: bool = True
    # Syslog listener (UDP + TCP). Default port 5514 (unprivileged).
    syslog_enabled: bool = False
    syslog_host: str = "0.0.0.0"
    syslog_udp_port: int = 5514
    syslog_tcp_port: int = 5514
    # File tailer: comma-separated file paths to follow.
    file_tail_enabled: bool = False
    file_tail_paths: str = ""
    file_tail_source_type: str = "auto"

    def file_tail_path_list(self) -> list[str]:
        return [p.strip() for p in self.file_tail_paths.split(",") if p.strip()]

    # --- HTTP / CORS ---
    # Comma-separated list of allowed origins. "*" only for local dev.
    cors_origins: str = "*"

    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    # --- Auth / security (Phase 4) ---
    # JWT signing secret. MUST be overridden in any non-local deployment.
    jwt_secret: str = "soc-simulator-dev-secret-change-me"
    jwt_expire_minutes: int = 480
    # Login rate limit (attempts per IP per window).
    login_rate_limit: int = 10
    login_rate_window_seconds: int = 60
    # Ingest rate limit (requests per key/IP per window; 0 disables).
    ingest_rate_limit: int = 0
    ingest_rate_window_seconds: int = 60

    def jwt_secret_is_default(self) -> bool:
        return self.jwt_secret == "soc-simulator-dev-secret-change-me"

    # --- Log retention (OpenSearch ISM) ---
    # Delete indices older than this many days (0 disables the policy).
    log_retention_days: int = 90


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
