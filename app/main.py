"""FastAPI entry point: REST API plus the static dashboard."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

from .models import ScanRequest, ScanResponse
from .scanner import ScanError, scan_url

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="Security Header Scanner",
    version="1.0.0",
    description=(
        "Inspect a website's HTTP response headers for common security headers "
        "(HSTS, CSP, X-Frame-Options, and more) and return a graded report."
    ),
)


@app.get("/api/health", tags=["meta"])
async def health() -> dict[str, str]:
    """Liveness probe used by Docker and the deployment pipeline."""
    return {"status": "ok"}


@app.post("/api/scan", response_model=ScanResponse, tags=["scan"])
async def scan(request: ScanRequest) -> ScanResponse:
    """Scan a single URL and return its graded security-header report."""
    try:
        return await scan_url(str(request.url))
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# Serve the dashboard at the root. Mounted last so the API routes above win.
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="dashboard")
