# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Report privately via GitHub's **"Report a vulnerability"** button under the
repository's **Security** tab (Private Vulnerability Reporting). This keeps the
report confidential until a fix is available.

Please include:
- a description of the issue and its impact,
- steps to reproduce (or a proof of concept),
- affected component (backend API, ingestion, detection, frontend).

We aim to acknowledge reports within a few days and will keep you updated on
remediation. Responsible disclosure is appreciated — please give us a
reasonable window to fix before any public disclosure.

## Scope & hardening notes

This is a self-hosted application. Before exposing an instance beyond localhost:

- Set a strong `JWT_SECRET` (or rely on the auto-generated persisted secret).
- Set `DEMO_MODE=false` so the sample training accounts are **not** created; an
  admin password is generated and printed once on first run.
- Restrict `CORS_ORIGINS` to your real frontend origin.
- Enable MFA for privileged accounts (Security page).
- Terminate TLS at a trusted reverse proxy; the app trusts `X-Forwarded-For`
  for client IPs (rate limiting, audit), so ensure the proxy sets it.
- Change default OpenSearch / Postgres credentials in `docker-compose.yml`.
