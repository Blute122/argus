# SOC Simulator → Argus (Real SIEM): Transformation Plan

**Status:** Phase 1 implemented. Phases 2–5 pending.
**Author:** Engineering
**Date:** 2026-07-02
**Scope:** Real log ingestion · Real detection engine · Scalable storage/search backend (OpenSearch) · Production hardening.
**Distribution model (decided 2026-07-02):** **Open-source, self-hosted.** Each user deploys their own instance (à la Wazuh / Security Onion). No multi-tenancy or billing. See Appendix A for the trade-off analysis and why this was chosen over SaaS. One structural hedge is carried forward regardless (see Phase 2 `tenant_id`).

---

## 1. Guiding principle

The current codebase is **not** thrown away. It already implements ~70% of a real SIEM: FastAPI app shell, JWT auth + RBAC roles, alert/incident/asset data models and workflow, a stateful correlation engine, MITRE ATT&CK mapping, an SPL-like hunt query parser, a report generator, and a full React dashboard with live WebSocket streaming.

What makes it a *simulation* is essentially **one layer**: data is procedurally generated (`backend/log_generators/`, `backend/attack_simulator/`) and persisted/queried in SQLite. This plan swaps that data plane for real ingestion + a search engine, upgrades detection from hardcoded Python to a real rule engine, and hardens the app for production — **while keeping the demo working** behind a flag so training value is not lost.

### Design tenets
- **Two-store split.** Logs (high-volume, append-only, full-text) live in **OpenSearch**. Metadata (users, incidents, alerts, assets, saved hunts, audit) stays in a relational DB — **migrate SQLite → PostgreSQL**. This is the correct split; do not force logs into Postgres or metadata into OpenSearch.
- **Stable normalized schema.** All logs conform to one ECS-inspired document shape regardless of source. Parsers translate raw source formats into it. The frontend and detection engine only ever see the normalized shape.
- **Every phase is independently shippable** and leaves the app in a working state.
- **Backwards compatibility for the UI.** The React app's contract (`services/api.ts`, WebSocket channels) changes as little as possible; endpoints keep their shapes, their backing store changes underneath.

---

## 2. Target architecture

```
  REAL SOURCES              INGESTION              PROCESSING            STORAGE            SERVING
┌───────────────┐      ┌──────────────────┐   ┌──────────────────┐  ┌────────────┐   ┌──────────────┐
│ Syslog (RFC   │─────▶│ Syslog listener  │   │ Parser registry  │  │ OpenSearch │   │ FastAPI REST │
│ 3164/5424)    │ udp/ │ (udp/tcp :514)   │──▶│ raw → normalized │─▶│  (logs-*   │◀─│ /api/logs    │
│               │ tcp  │                  │   │ ECS document     │  │  indices,  │  │ /api/hunt    │
├───────────────┤      ├──────────────────┤   ├──────────────────┤  │  ISM       │  │ /api/dash..  │
│ Agents/Beats/ │─────▶│ HTTP bulk        │──▶│ Enrichment       │─▶│  retention)│  ├──────────────┤
│ Vector/curl   │ http │ POST /ingest     │   │ (geo, threat-    │  │            │  │ WebSocket    │
├───────────────┤      ├──────────────────┤   │  intel, asset)   │  └────────────┘  │ /ws/logs     │
│ Log files     │─────▶│ File tailer      │──▶├──────────────────┤  ┌────────────┐  │ /ws/alerts   │
│ (.log/.json)  │      │ (watchdog)       │   │ DETECTION        │  │ PostgreSQL │  │ /ws/dashboard│
├───────────────┤      ├──────────────────┤   │ • Sigma engine   │─▶│ users,     │◀─│ /ws/incidents│
│ Demo generator│─────▶│ (DEMO_MODE flag) │──▶│ • existing rules │  │ incidents, │  └──────────────┘
│ (kept)        │      │                  │   │ • scheduled      │  │ alerts,    │        │
└───────────────┘      └──────────────────┘   │   searches       │  │ assets,    │   ┌──────────────┐
                                              └────────┬─────────┘  │ audit,     │   │ React (Vite) │
                                                       │            │ hunts      │   │ dashboard    │
                                                  alerts→PG +       └────────────┘   └──────────────┘
                                                  broadcast WS
```

Everything ships via **`docker-compose`**: `opensearch`, `opensearch-dashboards` (optional, admin), `postgres`, `backend`, `frontend`.

---

## 3. The normalized log schema (ECS-inspired)

A single document shape, indexed into OpenSearch time-based indices `logs-YYYY.MM.DD`. Field names align with [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) so external agents (Beats/Vector) map cleanly, with a compatibility layer for the current flat field names the frontend already uses.

| Normalized (ECS) field | Type | Maps from current `Log` column | Notes |
|---|---|---|---|
| `@timestamp` | date | `timestamp` | UTC, ISO-8601 |
| `event.kind` | keyword | (new) | `event` / `alert` / `signal` |
| `event.category` | keyword | derived from `source` | `authentication`, `network`, `process`, `email`, `iam` |
| `event.type` | keyword | `event_type` | e.g. `failed_login` |
| `event.code` | keyword | `event_id` | Windows Event ID |
| `event.severity` | keyword | `severity` | info/low/medium/high/critical |
| `event.outcome` | keyword | (new) | success/failure |
| `observer.vendor` / `observer.product` | keyword | `source` | `windows`/`linux`/`network`/… |
| `host.name` | keyword | `hostname` | |
| `user.name` | keyword | `username` | |
| `source.ip` / `source.port` | ip/long | `source_ip` / `source_port` | |
| `destination.ip` / `destination.port` | ip/long | `destination_ip` / `destination_port` | |
| `network.transport` | keyword | `protocol` | |
| `process.name` / `process.pid` | keyword/long | `process_name` / `process_id` | |
| `process.command_line` | text+keyword | `command_line` | |
| `file.path` | keyword | `file_path` | |
| `registry.key` | keyword | `registry_key` | |
| `dns.question.name` | keyword | `dns_query` | |
| `url.full` | keyword | `url` | |
| `user_agent.original` | text | `user_agent` | |
| `http.request.method` / `http.response.status_code` | keyword/long | `http_method` / `http_status` | |
| `source.bytes` / `destination.bytes` | long | `bytes_sent` / `bytes_received` | |
| `threat.tactic.name` | keyword | `mitre_tactic` | |
| `threat.technique.id` / `.name` | keyword | `mitre_technique` / `mitre_technique_name` | |
| `source.geo.country_name` / `.city_name` | keyword | `geo_country` / `geo_city` | enriched |
| `event.risk_score` | float | `confidence` | |
| `labels.is_malicious` | int | `is_malicious` | 0/1/2, kept for demo compat |
| `message` | text | `raw_log` | full-text searchable |
| `_meta.ingest_source` | keyword | (new) | `syslog`/`http`/`file`/`demo` |

An **OpenSearch index template** pins these mappings (keyword vs text vs ip vs date) so aggregations and term filters are exact and full-text works on `message`/`process.command_line`.

A thin **serialization helper** (`_fmt_log` equivalent) flattens a normalized doc back into the exact JSON keys the React app expects today (`source`, `source_ip`, `event_type`, `mitre_technique`, …), so `frontend/src/pages/LogStreamPage.tsx`, `HuntingPage.tsx`, etc. need **no changes** in early phases.

---

## 4. Phase plan

Each phase lists: goal · new/changed files · migration steps · how to verify · rollback.

### Phase 1 — Foundation & storage (OpenSearch + Postgres + compose) — ✅ IMPLEMENTED

> Delivered: `backend/config.py`, `backend/search/` (store abstraction + OpenSearch & SQL backends + query translator + index template), `docker-compose.yml`, `.env.example`, `backend/scripts/migrate_sqlite_to_pg.py`, root `README.md`. `main.py` and `api/logs.py` repointed to the store. App verified running on the SQLite fallback path; OpenSearch path enabled via `OPENSEARCH_ENABLED=true`.
> **Deviation from original design:** the OpenSearch document keeps the existing *flat* field names (typed via index template) rather than fully-nested ECS. Rationale: 1:1 mapping with the legacy query parser + trivial frontend serializer + lower risk. Full ECS aliasing moves to Phase 2 (where external agents make it matter).

**Goal:** Real search backend. Logs written to and queried from OpenSearch; metadata on Postgres; whole stack runs via `docker-compose`. Demo generator still produces the data, so nothing visibly breaks — but it's now flowing through a real store.

**New files**
- `docker-compose.yml` — services: `opensearch` (single-node, security demo config), `opensearch-dashboards`, `postgres`, `backend`, `frontend`.
- `backend/search/client.py` — OpenSearch client factory (env-configured host/auth/TLS), index-template bootstrap, `bulk_index()`, `search()`, `aggregate()` helpers.
- `backend/search/schema.py` — the normalized document model (Pydantic) + `to_document()` / `to_frontend_json()` converters + the index template JSON.
- `backend/search/indices.py` — index naming (`logs-{date}`), template install, ISM policy install.
- `backend/config.py` — central `pydantic-settings` config (DB URL, OpenSearch URL/creds, `DEMO_MODE`, JWT secret, CORS origins, etc.). Replaces scattered `os.getenv`.
- `.env.example` — documented env vars.
- `backend/migrations/` — Alembic already a dependency; wire it up for the Postgres metadata schema.

**Changed files**
- `backend/database/connection.py` — default to Postgres via `config.py`; keep SQLite fallback for local dev without Docker.
- `backend/main.py` (`log_generation_loop`, lines 34–95) — instead of `db.add(Log(...))`, build a normalized doc and `bulk_index()` to OpenSearch. Alerts still go to Postgres. WebSocket broadcast unchanged.
- `backend/main.py` (`_get_dashboard_stats`, lines 98–131) — replace the `func.count`/`group_by` log queries with **OpenSearch aggregations** (`source_distribution`, `top_attackers`, `total_logs`). Alert/asset counts stay on Postgres.
- `backend/api/logs.py`
  - `get_logs` (37–52) → OpenSearch query with `source`/`event_type`/`severity` term filters, sort by `@timestamp desc`, size/from paging.
  - `get_log_stats` (55–60) → OpenSearch aggregations.
  - `_fmt_log` (173–183) → read from a normalized hit's `_source` instead of an ORM row.
- Remove `log` from the relational `init_db()` model list (`connection.py:48`); the `logs` table is retired. `HuntQuery`, `Alert`, `Incident`, `Asset`, `User` stay relational.

**Data migration**
- One-off script `backend/scripts/migrate_sqlite_to_pg.py`: copy existing SQLite metadata tables (users/incidents/alerts/assets/hunts) into Postgres. Historical demo `logs` rows are **not** migrated (ephemeral) — optional `--include-logs` flag reindexes them into OpenSearch for testers who want history.

**Verify**
- `docker-compose up`, confirm OpenSearch green, index template installed.
- Log in, watch Log Stream page populate (now served from OpenSearch), Dashboard stats update, hunt returns results (Phase 1 keeps the SQL parser against a temporary shim OR moves it in this phase — see note below).

> **Query-parser note:** `utils/query_parser.py:build_filter` returns a *SQLAlchemy* expression. In Phase 1 the `/api/hunt` endpoint must instead produce an **OpenSearch query DSL**. I'll add `backend/search/query_translator.py` that reuses the existing tokenizer/field-alias/time-parse logic (lines 74–144 are store-agnostic and portable) but emits `bool`/`must`/`should`/`must_not` + `range`/`wildcard`/`match` clauses. `FIELD_ALIASES` and `NUMERIC_FIELDS` carry over; add mappings to ECS field names. This is the one non-trivial rewrite in Phase 1.

**Rollback:** `DEMO_MODE=true` + `DATABASE_URL=sqlite` + an `OPENSEARCH_ENABLED=false` fallback that routes logs back to the SQLite `Log` table keeps the old path alive during transition.

---

### Phase 2 — Real ingestion — ✅ IMPLEMENTED

> Delivered: `backend/ingestion/` — `pipeline.py` (shared normalize→store→detect→broadcast path; the demo generator now routes through it too, removing the duplicated loop in `main.py`), `parsers/` (registry + json-passthrough + RFC 3164/5424 syslog), `http_ingest.py` (`POST /api/ingest`, `/api/ingest/bulk`, plus admin key CRUD), `syslog_server.py` (UDP+TCP), `file_tailer.py` (offset-polling), `enrichment.py`, `bootstrap.py` (first-run ingest key). New `models/ingest_key.py` (sha256-hashed API keys → tenant). `tenant_id` added to the log schema/model with an idempotent additive migration in `connection.py`. Config gained `ingest_*`, `syslog_*`, `file_tail_*`, `default_tenant`. Verified end-to-end via TestClient (auth 401s, single + bulk NDJSON ingest).
> **Deviations from original design:** (1) `tenant_id` is carried on **log documents** (the expensive-to-retrofit part) but **not yet** on metadata tables — those are cheap `ALTER`s deferred to when multi-tenancy is actually built. (2) File tailer uses **offset polling** instead of `watchdog`, and enrichment ships **normalization only** with GeoIP/threat-intel/asset-correlation as documented hooks — this avoids the `watchdog`/`geoip2` dependencies, keeping the self-host install lean. Wire them in when a data source exists.

**Goal:** Accept logs from the outside world, not just the generator.

**`tenant_id` hedge (do it here).** Add an `org_id`/`tenant_id` field to the log document schema and metadata tables, defaulting every record to a single `"default"` org. For the open-source self-host model this is invisible (one org per deployment), but it is the expensive structural piece to retrofit later — carrying it now keeps a future hosted/multi-tenant tier possible at near-zero present cost. All ingestion paths stamp the tenant from the authenticating ingest key.

**New files**
- `backend/ingestion/pipeline.py` — the shared path: `raw bytes/dict → parse → normalize → enrich → detect → index + broadcast`. Everything below feeds this.
- `backend/ingestion/syslog_server.py` — asyncio UDP + TCP listeners on `:514` (configurable). RFC 3164 & 5424 framing.
- `backend/ingestion/http_ingest.py` — `POST /api/ingest` (single) and `POST /api/ingest/bulk` (NDJSON, Beats/Vector-compatible). API-key auth via `ingest_keys` table, separate from user JWTs.
- `backend/ingestion/file_tailer.py` — `watchdog`-based tailer for configured file globs (`.log`, `.json`, `.evtx`-export). Tracks offsets.
- `backend/ingestion/parsers/` — pluggable registry:
  - `base.py` (interface `parse(raw) -> normalized dict | None`)
  - `syslog_rfc.py`, `windows_evtx_json.py`, `linux_auth.py`, `nginx_access.py`, `json_passthrough.py`
  - `registry.py` (select parser by source hint / content sniff)
- `backend/ingestion/enrichment.py` — geoip (MaxMind GeoLite2), threat-intel lookup (reuse/extend `utils/threat_intel.py`), asset-correlation (match `host.name`/`ip` to `assets` table → attach `asset.criticality`).

**Changed files**
- `backend/main.py` lifespan (134–145) — start syslog listeners + file tailers as background tasks **only when configured**; gate the demo generator behind `if settings.DEMO_MODE`.
- New deps in `requirements.txt`: `opensearch-py`, `watchdog`, `geoip2`, `psycopg2-binary`.

**Verify**
- `logger -n localhost -P 514 "test event"` (or a PowerShell UDP send) appears in Log Stream.
- `curl -XPOST /api/ingest/bulk` with sample Winlogbeat NDJSON → parsed, normalized, visible, and (if it matches) alerts fire.
- Point a real Vector/Filebeat agent at `/api/ingest/bulk` end-to-end.

**Rollback:** listeners are opt-in via config; unset the ports and only `DEMO_MODE` runs.

---

### Phase 3 — Real detection engine (Sigma) — ✅ IMPLEMENTED

> Delivered: `backend/detection/` — `sigma.py` (native Sigma-subset matcher: selections, `|contains/startswith/endswith/re/gt/gte/lt/lte`, list-OR / `|all`-AND, boolean `condition` with `and/or/not/()` + `all of`/`1 of them`/`prefix*`), `threshold.py` (scheduled aggregation rules via `store.hunt`), `loader.py`, `engine.py` (loads YAML, syncs `detection_rules` table preserving enable/stats, evaluates streaming rules), `scheduler.py` (30s threshold runner with dedup). Starter pack in `rules/`: 8 streaming Sigma rules + 1 brute-force threshold rule (ported from the old correlation rules). New `models/detection_rule.py`, `api/rules.py` (list/detail-with-YAML/enable/disable/test; manage = admin/threat_hunter). Pipeline runs Sigma engine alongside a trimmed `CorrelationEngine` (now only the stateful APT killchain, to avoid duplicate alerts). Frontend `RulesPage.tsx` + nav + API. Also fixed the Phase 1 query translator to fold AND/OR left-to-right (needed for mixed threshold queries). Verified: streaming fires once (no dup), brute-force threshold fires, rules API + enable/disable/test all green; frontend typechecks.
> **Deviation:** implemented a **native Sigma-subset evaluator** rather than `pySigma` + `pysigma-backend-opensearch`. Reason: streaming evaluation runs on the event dict in-process, so detection works identically on **both** the OpenSearch and SQLite stores, with no heavy dependency and full local testability. Threshold rules query via the store's existing hunt (store-agnostic). Full pySigma/OpenSearch-native compilation can be added later for very high event volumes.

**Goal:** Detections become versioned rule content, not hardcoded Python — and run against real ingested logs.

**New files**
- `backend/detection/sigma_engine.py` — load Sigma YAML rules, compile to OpenSearch queries via **`pySigma` + `pysigma-backend-opensearch`**. Two execution modes:
  1. **Streaming** — for each doc in the pipeline, evaluate cheap field-match Sigma rules in-process (fast path).
  2. **Scheduled search** — a background scheduler runs aggregation/threshold Sigma rules (e.g. "5 failed logins in 5 min") as OpenSearch queries on an interval. This is what real SIEMs do and it replaces the fragile in-memory `context` counters in `correlation_engine/rules.py` (e.g. `BruteForceRule` lines 27–60).
- `backend/detection/rules/` — starter Sigma pack (brute force, suspicious PowerShell, C2 beacon, lateral movement, port scan, DNS exfil, phishing, priv-esc) — direct ports of the 9 existing `CorrelationRule` classes to YAML, plus a curated subset of the public SigmaHQ ruleset.
- `backend/detection/scheduler.py` — interval runner for scheduled rules; writes matches as alerts.
- `backend/api/rules.py` — CRUD for detection rules (list/enable/disable/test), so analysts manage rules from the UI. RBAC: `admin`/`threat_hunter` only.

**Changed files**
- `backend/correlation_engine/rules.py` — **kept** for stateless real-time rules (they're a legitimate fast path), but stateful/counting rules migrate to scheduled Sigma searches. `CorrelationEngine.process_log` (331–341) is called from `ingestion/pipeline.py` instead of only the demo loop.
- `backend/main.py` — start `detection/scheduler.py` in lifespan.
- Alert creation stays identical (same `Alert` model, same `broadcast_alert`, same escalation-to-incident path in `api/logs.py`), so the incident workflow and UI are untouched.

**New frontend (small)**
- `frontend/src/pages/RulesPage.tsx` — list/enable/disable/test detection rules; shows rule YAML, MITRE mapping, last-fired. Wire into `Sidebar.tsx` + `api.ts`.

**Verify**
- Ingest a crafted brute-force sequence → scheduled Sigma rule fires an alert → appears on Alerts page → escalates to incident.
- Disable a rule in the UI → confirm it stops firing.

---

### Phase 4 — Production hardening (self-host profile) — ✅ IMPLEMENTED

> Delivered: **RBAC enforcement** (admin-only `register`/`list_users` — closes a self-register-as-admin privilege-escalation hole; incident status → responder tier; asset create/update/vuln → responder tier). **Audit log** (`models/audit_log.py`, `backend/audit.py` helper, admin `api/audit.py`) recording login success/failure, MFA changes, rule enable/disable, incident/asset status changes, user + ingest-key creation. **JWT secret from config** (`settings.jwt_secret`, startup warning on default). **CORS** no longer sends credentials with `*` origins. **Rate limiting** (`backend/ratelimit.py`, dependency-free) on login + ingest. **MFA/TOTP** (`backend/mfa.py`, stdlib RFC 6238 — no pyotp/qrcode dep) with enroll/activate/disable endpoints and login enforcement. **ISM retention** policy installed on the OpenSearch path (`log_retention_days`). Frontend `SecurityPage.tsx` (MFA enrollment + admin audit viewer). Verified end-to-end via TestClient (RBAC 403s, admin-only register, MFA-enforced login, audit trail, rate limiter); frontend typechecks.
> **Deferred (deliberately):** OIDC/SSO — build on demand when an org needs IdP federation (see the auth-scope decision). MFA QR image uses manual secret entry rather than bundling a QR library.

**Goal:** Not a toy. Real access control, auditability, deployability — scoped for a *self-hosted single-org* operator, not a SaaS. That means: secure-by-default config, no secrets in the repo, HTTPS guidance, RBAC enforcement, audit log, and optional MFA/SSO — but **no** multi-tenant isolation, billing, metering, or SOC 2 program (those belong to a SaaS model, deliberately out of scope; see Appendix A).

**RBAC enforcement**
- Audit every route in `api/*.py`. Today many use `_user=Depends(get_current_user)` (authenticated but not authorized). Add a `require_role(...)` dependency and apply least-privilege: e.g. asset/rule/user writes → `admin`; incident close → `incident_responder`+; hunts → `threat_hunter`+; read dashboards → any authenticated. Roles already exist in `models/user.py` (`admin, analyst_l1-l3, threat_hunter, incident_responder`).

**Audit logging**
- New `audit_log` table + `backend/audit.py` middleware: record who did what (login, rule change, incident status change, data export) with timestamp, actor, IP, target. New `frontend/src/pages/AuditPage.tsx` (admin-only).

**AuthN hardening**
- Enforce MFA for privileged roles (`mfa_enabled` flag already on `User`); add TOTP enrollment/verify endpoints.
- Optional **OIDC/SSO** (`authlib`) so it federates to Okta/Entra/Keycloak.
- Move JWT secret to env/secret store (`config.py`), shorten token TTL, add refresh tokens.

**Transport & platform**
- Lock CORS to configured origins (currently `allow_origins=["*"]` in `main.py:159` — must not ship).
- Rate limiting (`slowapi`) on auth + ingest + hunt.
- Structured JSON app logs; `/metrics` (Prometheus) for EPS, ingest lag, rule latency, WS connections.
- OpenSearch **ISM retention policy** (hot 7d → warm 30d → delete 90d, configurable) for real retention/cost control.
- Production `docker-compose.prod.yml` + healthchecks + resource limits; secrets via env/Docker secrets; TLS termination notes (reverse proxy).

**Verify**
- An `analyst_l1` JWT is rejected (403) on admin routes; audit entries recorded; MFA required for admin login; CORS blocks an unlisted origin; old indices roll off per ISM.

---

### Phase 5 — Open-source packaging & release — ✅ IMPLEMENTED

> Delivered: `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`; GitHub Actions CI (`.github/workflows/ci.yml`) running backend import + `pytest backend/tests` and the frontend build; `backend/Dockerfile` + `frontend/Dockerfile` (+ `frontend/nginx.conf` proxying `/api` and `/ws`) so `docker compose up --build` runs the whole stack (UI on `:8080`); `.dockerignore`; secure first-run defaults — auto-generated persisted JWT secret and, when `DEMO_MODE=false`, an admin-only seed with a generated/`ADMIN_PASSWORD` password (demo accounts + sample assets gated to demo mode); README badges + full-stack instructions. Verified: 7 smoke tests pass, backend imports, frontend builds.

**Goal:** Make it something a stranger can deploy in minutes and trust. This is the "wrapper" the self-host model needs; the SIEM engine itself is Phases 1–4.

**New files / work**
- `LICENSE` — **MIT, added** (chosen for simplicity; it's a learning project). Copyright holder currently `Bluet122`.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md` (vuln disclosure contact + policy).
- `.github/workflows/ci.yml` — lint + import/smoke tests on PRs; build/push versioned container images on tag.
- Containerize the app: `backend/Dockerfile`, `frontend/Dockerfile`, and extend `docker-compose.yml` with `backend` + `frontend` services so `docker compose up` runs the *entire* stack, not just infra.
- `docs/INSTALL.md` + `docs/CONFIGURATION.md` — quickstart, env reference (already partly in `README.md`/`.env.example`), upgrade notes, hardening checklist for internet-facing deploys.
- Versioning: semantic-version tags + a `CHANGELOG.md`; pin OpenSearch/Postgres image versions.
- Secure defaults: ship with `CORS_ORIGINS` locked, generated secrets on first boot (not hardcoded), and a first-run admin-password prompt instead of seeded demo creds.
- (Later, optional) a Helm chart for Kubernetes self-hosters.

**License recommendation.** Default to **Apache-2.0** (permissive + explicit patent grant — friendliest for adoption and a security-tool audience). If you want to preserve a future paid hosted tier and stop competitors from hosting your code without contributing back, choose **AGPL-3.0** instead (the common "open-core with hosted upsell" choice). This is a strategic decision — flag which way you lean and I'll add the file.

**Verify**
- Fresh clone → `docker compose up` → working dashboard with no manual steps beyond setting an admin password.
- CI green on a PR; a tagged release produces pullable images.

---

## 5. What each existing component becomes

| Current | Fate |
|---|---|
| `log_generators/*` | **Kept**, gated behind `DEMO_MODE`. Doubles as a load generator / demo. |
| `attack_simulator/*` (campaigns, scenarios) | **Kept** as purple-team feature — now injects into the *real* pipeline, so you can validate detections against known attacks. |
| `correlation_engine/rules.py` | **Kept** for stateless real-time rules; stateful ones move to scheduled Sigma. |
| `utils/query_parser.py` | Tokenizer/aliases/time-parsing **reused**; output retargeted from SQLAlchemy to OpenSearch DSL. |
| `models/log.py` (SQLite `logs`) | **Retired**; replaced by OpenSearch normalized docs. |
| `models/{alert,incident,asset,user,hunt_query}.py` | **Kept**, migrated SQLite → Postgres. |
| `api/incidents.py`, `api/reports.py`, `api/assets.py`, `api/mitre.py` | **Largely unchanged**; only their log-reads (if any) repoint to OpenSearch. |
| Frontend (all pages, `api.ts`, `useWebSocket.ts`) | **Unchanged** through Phase 2 via the compat serializer; Phase 3 adds `RulesPage`, Phase 4 adds `AuditPage`. |

---

## 6. Dependencies to add

**Backend:** `opensearch-py`, `psycopg2-binary`, `watchdog`, `geoip2`, `pysigma`, `pysigma-backend-opensearch`, `slowapi`, `authlib` (SSO, Phase 4), `prometheus-client`.

**Infra:** Docker + docker-compose; OpenSearch 2.x image; Postgres 16 image; MaxMind GeoLite2 DB (license key).

**Frontend:** none required (RulesPage/AuditPage use existing React/axios/echarts stack).

---

## 7. Risks & decisions still open

1. **OpenSearch resource footprint** on your Windows 11 dev box — single-node needs ~1–2 GB RAM via Docker Desktop. If that's tight, Phase 1 can run OpenSearch with reduced heap; flag if you want a lighter option.
2. **Query language scope** — the current parser is a small SPL subset. Do we keep that syntax (lower learning curve, reuses your code) or expose OpenSearch **DQL/Lucene** directly? *Recommendation: keep the SPL-ish syntax, translate to DSL — least UI churn.*
3. **Sigma streaming vs scheduled** — pure streaming can't do time-window aggregations; pure scheduled adds latency. *Recommendation: hybrid, as above.*
4. **Multi-tenancy** — *resolved:* distribution model is open-source self-host (Appendix A), so full multi-tenancy is out of scope. A single `tenant_id` defaulting to `"default"` is still carried in Phase 2 as a cheap hedge.
5. **Ordering** — plan assumes Phase 1 → 5 in sequence. Phases 2 and 3 could partly parallelize; Phase 5 (packaging) can start anytime. Phase 1 had to land first (everything depends on the store/schema) — it has.
6. **License choice** — *resolved:* **MIT** (simplicity for a learning project). `LICENSE` added.

---

## 8. Suggested first commit set (Phase 1)

1. `docker-compose.yml` + `.env.example` + `backend/config.py`
2. `backend/search/{client,schema,indices,query_translator}.py` + index template
3. Repoint `main.py` generation loop + dashboard stats + `api/logs.py` to OpenSearch
4. `connection.py` → Postgres default; `migrate_sqlite_to_pg.py`
5. Smoke test end-to-end; update README with run instructions

---

---

## Appendix A — Distribution model analysis (decided: open-source self-host)

The SIEM *engine* (ingestion, detection, search, retention — Phases 2–4) is identical across every distribution model. What differs is only the **wrapper**. Three options were weighed:

| Dimension | **Open-source self-host** (chosen) | Single-org internet-facing | Multi-tenant SaaS |
|---|---|---|---|
| Time to launch | Weeks | Weeks–1 month | Many months (team-sized) |
| Effort beyond Phases 1–4 | Packaging, docs, secure defaults, install (Phase 5) | Full Phase 4 + deploy ops | + tenancy, billing, compliance, HA |
| Ongoing ops burden | Low (users run it) | Medium (you run 1 instance) | High, continuous (24/7, on-call) |
| Liability | Low — you hold no one's data | Medium — one org's data | High — many orgs' security logs |
| Compliance | None on you | Depends on the org | SOC 2 effectively mandatory; GDPR; DPAs |
| Cost to run | ~$0 | Modest (one cloud env) | Significant (cluster + tooling + staff) |
| Revenue model | Open-core, support, consulting, later a hosted tier | Contract/consulting | Subscriptions — highest ceiling, longest road |
| Reuses existing work | ✅ `docker-compose.yml` is ~80% of it | Mostly | Least |

**Why self-host:** fastest path to "public," minimal liability, reuses the Docker stack, strong credibility/portfolio artifact, and it can *become* SaaS later without rework (thanks to the Phase 2 `tenant_id` hedge). SaaS was rejected for now as a company-sized commitment in a crowded market (Splunk, Elastic, Sentinel, Datadog, Panther).

**Recommended ladder if ambitions grow:** OSS self-host → (optional) single-org hosted instance = Phase 4 hardening + a deploy → SaaS only if real demand/funding appears.

---

*Phase 1 shipped and verified. Phase 2 (real ingestion) is next. Review the updated phases (2–5) and Appendix A; flag the license choice (§7.6) when convenient.*
