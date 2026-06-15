"""Scan orchestration: fetch headers, then grade them."""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.schemas import ScanResponse
from app.scanner.fetch import HeaderFetcher
from app.scoring.grader import grade_headers


async def scan(url: str, fetcher: HeaderFetcher) -> ScanResponse:
    """Fetch ``url`` via ``fetcher`` and return a fully graded report."""
    result = await fetcher.fetch(url)
    grade = grade_headers(result.headers)

    return ScanResponse(
        url=url,
        final_url=result.final_url,
        status_code=result.status_code,
        score=grade.score,
        grade=grade.grade,
        headers_present=grade.headers_present,
        headers_missing=grade.headers_missing,
        findings=grade.findings,
        info_disclosure=grade.info_disclosure,
        scanned_at=datetime.now(UTC).isoformat(),
    )
