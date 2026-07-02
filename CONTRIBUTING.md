# Contributing

Thanks for your interest in improving this project! Contributions of all kinds
are welcome — bug fixes, detection rules, docs, and features.

## Development setup

**Backend** (Python 3.12+):
```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt pytest
cd ..
uvicorn backend.main:app --reload
```

**Frontend** (Node 20+):
```bash
cd frontend
npm install
npm run dev
```

Defaults run with SQLite + the synthetic log generator, so no external infra is
required. For the full stack (OpenSearch + Postgres), see the README.

## Running checks

```bash
# backend tests
PYTHONPATH=. pytest -q backend/tests

# frontend type-check + build
cd frontend && npm run build
```

CI runs both on every PR; please make sure they pass.

## Adding a detection rule

Drop a `.yml` file in `backend/detection/rules/` (see existing rules for the
Sigma-style format). Streaming rules match per event; `type: threshold` rules
run on a schedule. Test yours from the **Detection Rules** page or
`POST /api/detection/rules/{id}/test`.

## Pull requests

1. Fork and branch from `main` (`git checkout -b feat/my-change`).
2. Keep changes focused; add/adjust tests where it makes sense.
3. Run the checks above.
4. Open a PR describing the change and the motivation.

## Guidelines

- Match the surrounding code style; keep functions small and readable.
- No secrets in commits. `.env`, `data/`, and generated secrets are gitignored.
- Security-sensitive changes (auth, ingestion, rules) get extra review — call
  them out in the PR description.

By contributing you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
