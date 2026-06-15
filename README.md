# Security Header Scanner

A small web app that inspects a website's HTTP response headers for the security
headers that matter (HSTS, CSP, X-Frame-Options, and more), grades the result
from **A+ to F**, and explains how to fix what's missing. It ships with a
dashboard, a REST API, and a full **DevSecOps CI/CD pipeline** that builds,
tests, security-scans, and deploys the app to a self-hosted home server.

> Built as a portfolio project to demonstrate practical software engineering and
> security tooling: FastAPI, Docker, automated testing, SAST, container
> scanning, and continuous deployment.

## Features

- **Header grading** — checks HSTS, Content-Security-Policy, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, and Permissions-Policy, weighted by
  severity, and flags information-disclosure headers (`Server`, `X-Powered-By`).
- **REST API** — `POST /api/scan` returns a structured JSON report; interactive
  docs at `/docs`.
- **Dashboard** — a clean single-page UI for running scans in the browser.
- **SSRF protection** — refuses to scan loopback, private, link-local, or
  reserved addresses by default (see `app/scanner.py`).
- **Containerized** — runs as a non-root user with a Docker health check.

## Architecture

```
app/
  main.py        FastAPI app: REST API + static dashboard
  scanner.py     Network fetch (scan_url) + pure grading logic (analyze_headers)
  models.py      Pydantic request/response models
  static/        Dashboard (HTML/CSS/JS, no framework)
tests/           Unit tests (grading, SSRF guard) + API tests (TestClient)
.github/workflows/
  ci.yml         Lint -> test -> SAST -> build -> image scan -> push to GHCR
  codeql.yml     CodeQL static analysis
  deploy.yml     Self-hosted deploy on the home server after CI succeeds
```

The network layer and the grading logic are deliberately separated so the
scoring can be unit-tested without making real HTTP requests.

## Run locally

### With Python

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 for the dashboard, or http://127.0.0.1:8000/docs
for the API.

### With Docker

```bash
docker compose up --build
```

Then open http://127.0.0.1:8080.

## API

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
  "score": 47,
  "grade": "F",
  "headers_present": 2,
  "headers_missing": 4,
  "findings": [ ... ],
  "info_disclosure": { "Server": "ECS" },
  "scanned_at": "2026-06-15T17:00:00+00:00"
}
```

## Tests

```bash
pytest --cov=app --cov-report=term-missing
```

## The CI/CD pipeline

Every push and pull request to `main` runs **`ci.yml`**:

1. **Lint & format** — `ruff check` and `ruff format --check`.
2. **Test** — `pytest` with coverage gated at 85%.
3. **SAST** — `bandit` static analysis of the application code.
4. **Build** — builds the Docker image.
5. **Image scan** — `Trivy` fails the build on HIGH/CRITICAL CVEs.
6. **Push** — on `main`, publishes the image to GitHub Container Registry (GHCR).

`codeql.yml` adds GitHub's CodeQL static analysis, and Dependabot keeps the
pip, Docker, and Actions dependencies patched.

### Continuous deployment to the home server

`deploy.yml` triggers after CI succeeds on `main` and runs on a **self-hosted
runner** on the home server. The cloud does the heavy lifting (build, tests,
scans); the home server only pulls the finished image and restarts the
container, so its compute footprint is minimal.

One-time runner setup on the server:

1. GitHub repo → **Settings → Actions → Runners → New self-hosted runner**, and
   follow the steps. Give it the label `homelab`.
2. Add a repository secret `GHCR_TOKEN` (a PAT with `read:packages`) so the
   runner can pull the image, or make the GHCR package public.
3. Place `docker-compose.yml` in the runner's working directory.

After that, every merge to `main` automatically redeploys.

## License

MIT — see [LICENSE](LICENSE).
