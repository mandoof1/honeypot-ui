# Contributing to HoneySentinel

Thanks for wanting to help with the honeypot platform. This is a collaborative
project — contributions are welcome from everyone.

## Getting started

1. Fork the repository and clone your fork.
2. Use a feature branch for your change.
3. Describe the behavior before and after your change.
4. Run the checks relevant to your change before opening a pull request.

## Local stack

For the full stack, install **Docker Engine with Compose v2**, **Git**, and
**Python 3**.

```bash
git clone <your-fork>
cd honeypot-ui
./start.sh
```

The startup script creates `.env` when absent and generates separate signing,
encryption, and ingest secrets. Compose starts PostgreSQL, the API, frontend,
and engine. Demo seeding is enabled for an empty local database.

**Exposure matters:** Compose publishes the emulated service ports on the host.
Use an isolated development machine or network, and review port bindings before
starting. Keep generated credentials private.

## Frontend

Use **Node.js 24**. The frontend is React 19 + Vite 8 + Tailwind CSS 4.

```bash
npm ci
npm run dev
```

The default API URL is `http://localhost:8000/api/v1`. Set `VITE_API_URL`
before building when your backend is elsewhere.

```bash
npm run check                   # Lint, API-client tests, production build
npx playwright install chromium
npm run test:e2e                 # Desktop/mobile browser tests of the built app
```

Browser tests use synthetic API fixtures; they do not replace testing a
deployed stack.

## Backend

Use **Python 3.12**.

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r backend/requirements-test.txt -r honeypot/requirements.txt
.venv/bin/python -m pytest backend/tests -q
.venv/bin/python -m pytest honeypot/tests -q
```

Tests use isolated SQLite and do not require production credentials or a live
engine.

## Pull requests

* Keep PRs small and focused on a single change.
* Explain what changed and why in the PR description.
* Use synthetic test data in tests and screenshots.

**Never commit** `.env` files, access tokens, captured credentials, or any real
session evidence.

## Reporting issues

Use the issue templates. For security issues, see [SECURITY.md](SECURITY.md)
and report privately instead of opening a public issue.

## Code of conduct

By participating you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).