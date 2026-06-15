"""Application entry point: assembles the API and the static dashboard."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes import router

STATIC_DIR = Path(__file__).parent / "static"

DESCRIPTION = (
    "Inspect a website's HTTP response headers for common security headers "
    "(HSTS, CSP, X-Frame-Options, and more) and return a graded report."
)


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    app = FastAPI(title="Security Header Scanner", version="1.0.0", description=DESCRIPTION)
    app.include_router(router)
    # Serve the dashboard at the root; mounted last so the API routes win.
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="dashboard")
    return app


app = create_app()
