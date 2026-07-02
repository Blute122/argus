# Argus

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/Blute122/argus/actions/workflows/ci.yml/badge.svg)](https://github.com/Blute122/argus/actions/workflows/ci.yml)

**Argus** is a self-hostable Security Operations Center / SIEM: live log stream, real log
ingestion, Sigma-style detection rules, correlation-based alerting, threat
hunting (SPL-like syntax), incident response workflow, asset inventory, MITRE
ATT&CK mapping, and attack simulation.

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

## Full stack with Docker (OpenSearch + Postgres + backend + frontend)

One command builds and runs everything:

```bash
docker compose up --build
```

Then open the dashboard at **http://localhost:8080**. Services:
OpenSearch `:9200`, Dashboards `:5601`, Postgres `:5432`, API `:8000`, UI `:8080`.

- Logs are stored in OpenSearch (time-based `logs-YYYY.MM.DD` indices); metadata
  in Postgres. The JWT secret auto-generates into a mounted volume.
- `DEMO_MODE=true` (the compose default) ships sample data + training logins
  (`admin` / `admin123`). Set `DEMO_MODE=false` in `docker-compose.yml` for a
  real deployment — an **admin password is generated and printed once** in the
  backend logs, and the sample accounts/assets are not created.
- Change the default OpenSearch/Postgres credentials before exposing the stack.

To run the backend against these services **without** containerizing it, set in
`backend/.env`: `OPENSEARCH_ENABLED=true`, `OPENSEARCH_PASSWORD=Soc!Secur3Pass`,
`DATABASE_URL=postgresql+psycopg2://soc:soc@localhost:5432/soc`, then start
uvicorn. To move existing SQLite metadata over:
`python -m backend.scripts.migrate_sqlite_to_pg` (`--include-logs` also reindexes
old logs into OpenSearch).

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

## Detection rules

Detections are **Sigma-style YAML rules** in `backend/detection/rules/`, evaluated
two ways:
- **streaming** — matched against every event as it's ingested (in-process, works
  on any store)
- **scheduled** — `type: threshold` rules run every 30s over a time window (e.g.
  "5+ failed logins from one IP in 5 min")

Manage them in the **Detection Rules** page (enable/disable, view YAML, test
against recent logs) or via the API (`/api/detection/rules`). Toggling requires
the `admin` or `threat_hunter` role.

Add your own rule by dropping a `.yml` file in the rules directory:

```yaml
title: Suspicious PowerShell Execution
id: my-powershell-rule
level: critical
detection:
  selection:
    event_type: powershell_execution
    command_line|contains: ['-enc', 'frombase64']
  condition: selection
tags: [attack.execution, attack.t1059.001]
recommended_action: Isolate host, review parent process tree.
```

The matcher supports the common Sigma constructs (field modifiers, list-OR,
`condition` with `and/or/not`, `all of`/`1 of them`), so many public SigmaHQ
rules work with little or no change.

## Configuration

All settings live in [backend/config.py](backend/config.py) and are read from
environment / `.env`. See [.env.example](.env.example) for the full list.

| Var | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./argus.db` | Relational metadata store |
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
saved hunts) lives in the **relational DB**. Ingestion, detection, and hardening
live in [backend/ingestion/](backend/ingestion/),
[backend/detection/](backend/detection/), and the auth/audit layer. See
[docs/SIEM_TRANSFORMATION_PLAN.md](docs/SIEM_TRANSFORMATION_PLAN.md) for the full
design.

## Contributing & security

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). To report a
vulnerability, follow [SECURITY.md](SECURITY.md) (please don't open a public
issue). Licensed under [MIT](LICENSE).
