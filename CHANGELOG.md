# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added — SIEM transformation

The project evolved from a SOC training simulation into a self-hostable SIEM:

- **Storage** — pluggable log store with an OpenSearch backend and a
  SQLite/Postgres fallback (`OPENSEARCH_ENABLED`). SPL-style hunt syntax is
  translated to OpenSearch query DSL. `docker-compose` for OpenSearch +
  Dashboards + Postgres.
- **Ingestion** — real log intake via HTTP bulk (`/api/ingest[/bulk]`), a
  syslog UDP/TCP listener, and a file tailer, with pluggable parsers
  (JSON passthrough, RFC 3164/5424 syslog) and API-key auth. The synthetic
  generator is retained behind `DEMO_MODE`.
- **Detection** — Sigma-style YAML rules evaluated per event (streaming) and on
  a schedule (threshold rules). Rule management API + UI; rules ship as version-
  controlled YAML.
- **Hardening** — RBAC enforcement, audit log, MFA/TOTP, rate limiting,
  config-driven JWT secret, CORS lockdown, and OpenSearch ISM retention.
- **Packaging** — full-stack `docker compose up` (backend + frontend + infra),
  CI, tests, secure first-run defaults (generated JWT secret and admin
  password), and an MIT license.

### Security

- Fixed a privilege-escalation flaw where user registration was unauthenticated
  and accepted a client-supplied role (self-registration as admin). Registration
  is now admin-only.
