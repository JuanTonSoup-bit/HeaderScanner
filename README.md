# Security Header Scanner

A web app that inspects a website's HTTP response headers for the security
headers that matter (HSTS, CSP, X-Frame-Options, and more), grades the result
from **A+ to F**, explains *why*, and tells you how to fix what's missing. It
ships with a dashboard, a REST API, and a full **DevSecOps CI/CD pipeline** that
lints, type-checks, tests, security-scans, and deploys the app.

> A portfolio project demonstrating practical software engineering and security
> tooling: a layered FastAPI service, hardened against SSRF, with automated
> testing, SAST, dependency auditing, and container scanning in CI.

## Features

- **Value-aware grading** — doesn't just check whether a header is present, it
  judges the value (e.g. a short HSTS `max-age` or a CSP with `unsafe-inline`
  only earns partial credit).
- **SSRF protection** — scheme allowlist, rejection of private/loopback/
  link-local/reserved ranges, an explicit block on the cloud metadata endpoint,
  per-redirect re-validation, and IP-pinned connections to close the
  DNS-rebinding window. See [`app/scanner/ssrf.py`](app/scanner/ssrf.py).
- **REST API** — `POST /api/scan` returns a structured JSON report. Interactive
  OpenAPI docs at [`/docs`](http://127.0.0.1:8000/docs).
- **Dashboard** — a clean single-page UI showing per-header pass/warn/fail.
- **Containerized** — pinned multi-stage image, non-root user, health check.

## Quickstart

### Local (Python 3.12+)

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

Dashboard at http://127.0.0.1:8000, API docs at http://127.0.0.1:8000/docs.

### Docker

```bash
docker compose up --build
```

Then open http://127.0.0.1:8080.

## API example

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

```json
{
  "url": "https://example.com",
  "final_url": "https://example.com/",
  "status_code": 200,
  "score": 74,
  "grade": "C",
  "headers_present": 5,
  "headers_missing": 1,
  "findings": [
    {
      "name": "Content-Security-Policy",
      "status": "warn",
      "present": true,
      "points_awarded": 10,
      "points_possible": 20,
      "note": "Policy allows 'unsafe-inline'/'unsafe-eval', weakening XSS protection.",
      "...": "..."
    }
  ],
  "info_disclosure": { "Server": "ECS" },
  "scanned_at": "2026-06-15T17:00:00+00:00"
}
```

## Grading rubric

Each header earns points by severity; the total (76) is normalized to 0-100,
then 5 points are subtracted per information-disclosure header
(`Server`, `X-Powered-By`, `X-AspNet-Version`). Defined in
[`app/scoring/rubric.py`](app/scoring/rubric.py).

| Header | Severity | Max pts | Full credit | Partial credit (warn) |
| --- | --- | --- | --- | --- |
| Strict-Transport-Security | high | 20 | `max-age` ≥ 180 days | present but missing/short `max-age` |
| Content-Security-Policy | high | 20 | no `unsafe-inline`/`unsafe-eval` | allows `unsafe-inline`/`unsafe-eval` |
| X-Frame-Options | medium | 12 | `DENY` or `SAMEORIGIN` | other value |
| X-Content-Type-Options | medium | 12 | `nosniff` | other value |
| Referrer-Policy | low | 6 | any policy except `unsafe-url` | `unsafe-url` |
| Permissions-Policy | low | 6 | present | — |

Letter grades: **A+** ≥ 95, **A** ≥ 90, **B** ≥ 80, **C** ≥ 70, **D** ≥ 60,
**F** < 60.

## Architecture

```
app/
  config.py        Settings (pydantic-settings, 12-factor)
  main.py          App factory: wires the API router + static dashboard
  api/             Routing and dependency injection (thin)
  scanner/
    ssrf.py        URL/IP validation (the SSRF guard)
    fetch.py       SSRF-safe header fetching (injectable HTTP client)
    service.py     Orchestration: fetch -> grade
  scoring/
    rubric.py      The documented grading rules
    grader.py      Pure grade_headers() — no network, no framework
  models/          Pydantic request/response schemas
  static/          Dashboard (HTML/CSS/JS)
tests/             scoring, ssrf, fetch (mocked network), and API tests
```

The HTTP client is dependency-injected, so the network is fully mocked in tests.
The grading logic is pure and importable without starting the server.

## Tests

```bash
pytest --cov=app --cov-report=term-missing
```

## CI/CD & security

Every push and pull request runs [`ci.yml`](.github/workflows/ci.yml) with these
jobs in parallel, gating a final build:

1. **Lint & format** — `ruff`.
2. **Type check** — `mypy`.
3. **Tests** — `pytest` with an 85% coverage gate.
4. **SAST** — `bandit` (fails on medium+ findings).
5. **Dependency audit** — `pip-audit` against pinned requirements.
6. **Build, scan & push** — builds the image, scans it with **Trivy** (fails on
   HIGH/CRITICAL), and on `main` pushes to GitHub Container Registry.

[`codeql.yml`](.github/workflows/codeql.yml) adds CodeQL analysis, and Dependabot
keeps pip/Docker/Actions dependencies patched.

### Deployment

[`deploy.yml`](.github/workflows/deploy.yml) runs after CI succeeds on `main`,
on a **self-hosted runner** on the home server. The cloud does the heavy lifting
(build, tests, scans); the server only pulls the finished image and restarts the
container. The target host is never hardcoded — it is the runner itself, and the
registry token comes from the `GHCR_TOKEN` secret.

## License

MIT — see [LICENSE](LICENSE).
