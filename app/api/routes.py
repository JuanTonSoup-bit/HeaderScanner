"""API routes. Thin layer: validate input, delegate, map errors to HTTP codes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from app.config import Settings, get_settings
from app.models.schemas import ScanRequest, ScanResponse
from app.scanner.fetch import FetchError, HeaderFetcher
from app.scanner.service import scan
from app.scanner.ssrf import SSRFError

router = APIRouter(prefix="/api")


def get_fetcher(settings: Annotated[Settings, Depends(get_settings)]) -> HeaderFetcher:
    """Provide a HeaderFetcher. Overridable in tests via dependency_overrides."""
    return HeaderFetcher(settings)


@router.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    """Liveness probe used by Docker and the deployment pipeline."""
    return {"status": "ok"}


@router.post("/scan", response_model=ScanResponse, tags=["scan"])
async def scan_endpoint(
    request: ScanRequest,
    fetcher: Annotated[HeaderFetcher, Depends(get_fetcher)],
) -> ScanResponse:
    """Scan a single URL and return its graded security-header report."""
    try:
        return await scan(str(request.url), fetcher)
    except (SSRFError, FetchError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
