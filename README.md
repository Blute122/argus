# SOC Platform

A Security Operations Center dashboard: live log stream, correlation-based
alerting, threat hunting (SPL-like syntax), incident response workflow, asset
inventory, MITRE ATT&CK mapping, and attack simulation.

It runs in two modes:

- **Demo / zero-infra** — a synthetic log generator feeds the pipeline; logs are
  stored in SQLite. No Docker required. Great for training and development.
- **Real SIEM** — logs are stored and searched in **OpenSearch**, metadata in
  **Postgres**, with real ingestion and detection (see
  [docs/SIEM_TRANSFORMATION_PLAN.md](docs/SIEM_TRANSFORMATION_PLAN.md)).

The mode is controlled entirely by configuration — no code changes.

## Quick start (zero-infra, SQLite)

```bash
# backend
cd backend
python -m venv venv && venv\Scripts\activate      # Windows
pip install -r requirements.txt
cd .. && uvicorn backend.main:app --reload

# frontend
cd frontend
npm install
npm run dev
```

Defaults: `OPENSEARCH_ENABLED=false`, `DATABASE_URL=sqlite`, `DEMO_MODE=true`.
Copy `.env.example` to `.env` to override.

## Real-SIEM mode (OpenSearch + Postgres)

1. Start infrastructure:
   ```bash
   docker compose up -d          # OpenSearch :9200, Dashboards :5601, Postgres :5432
   ```
2. Configure `backend/.env` (or project-root `.env`):
   ```env
   OPENSEARCH_ENABLED=true
   OPENSEARCH_URL=https://localhost:9200
   OPENSEARCH_PASSWORD=Soc!Secur3Pass
   DATABASE_URL=postgresql+psycopg2://soc:soc@localhost:5432/soc
   DEMO_MODE=true          # keep the generator; set false once real ingestion is wired
   ```
3. (Optional) migrate existing SQLite metadata into Postgres:
   ```bash
   python -m backend.scripts.migrate_sqlite_to_pg
   # add --include-logs to also reindex old logs into OpenSearch
   ```
4. Start the backend as above. On boot it installs the OpenSearch index template
   and begins writing logs to time-based `logs-YYYY.MM.DD` indices.

## Sending real logs (ingestion)

Real logs enter through the ingestion pipeline (same path the demo generator
uses). Set `DEMO_MODE=false` once you have a real source so only real data shows.

On first boot the server prints a **default ingest key** (shown once) — copy it.
Admins can mint more via `POST /api/ingest/keys`.

**HTTP (agents, Beats, Vector, curl):**
```bash
# single event (JSON or a raw log line)
curl -X POST http://localhost:8000/api/ingest \
  -H "X-Ingest-Key: <your-key>" \
  -d '{"source":"windows","event_type":"failed_login","src_ip":"9.9.9.9","message":"4625"}'

# bulk: NDJSON, one JSON object or raw line per line
curl -X POST http://localhost:8000/api/ingest/bulk \
  -H "X-Ingest-Key: <your-key>" --data-binary @events.ndjson
```
Add `?source_type=syslog|json|auto` to force a parser (default `auto` sniffs).

**Syslog (RFC 3164 / 5424):** set `SYSLOG_ENABLED=true` (listens on udp/tcp
`5514` by default), then point devices at it:
```bash
logger -n localhost -P 5514 -d "test event"
```

**Files:** set `FILE_TAIL_ENABLED=true` and `FILE_TAIL_PATHS=/var/log/auth.log,/var/log/nginx/access.log`.
New lines are followed and ingested.

Custom formats: add a parser under `backend/ingestion/parsers/` and
`register("mytype", parse)`.

## Configuration

All settings live in [backend/config.py](backend/config.py) and are read from
environment / `.env`. See [.env.example](.env.example) for the full list.

| Var | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./soc_simulator.db` | Relational metadata store |
| `OPENSEARCH_ENABLED` | `false` | Use OpenSearch as the log store |
| `OPENSEARCH_URL` / `_USER` / `_PASSWORD` | `https://localhost:9200` / `admin` | OpenSearch connection |
| `DEMO_MODE` | `true` | Run the synthetic log generator |
| `INGEST_ENABLED` | `true` | Enable `/api/ingest` HTTP endpoints |
| `SYSLOG_ENABLED` | `false` | Start the syslog UDP+TCP listener |
| `SYSLOG_UDP_PORT` / `SYSLOG_TCP_PORT` | `5514` | Syslog listener ports |
| `FILE_TAIL_ENABLED` / `FILE_TAIL_PATHS` | `false` / `` | Follow files and ingest new lines |
| `CORS_ORIGINS` | `*` | Allowed frontend origins (lock down in prod) |

## Architecture

Logs (high-volume, append-only) live in the **log store** (OpenSearch, or SQLite
in demo mode) behind a common interface in
[backend/search/](backend/search/). Metadata (users, incidents, alerts, assets,
saved hunts) lives in the **relational DB**. See the transformation plan for the
full roadmap: real ingestion (syslog/HTTP/file), a Sigma detection engine,
retention policies, and production hardening.
