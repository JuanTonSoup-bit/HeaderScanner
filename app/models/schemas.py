"""Request and response schemas, shared across the API and scoring layers."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, HttpUrl


class CheckStatus(StrEnum):
    """Outcome of evaluating a single header."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class ScanRequest(BaseModel):
    """Incoming request: a single URL to inspect.

    ``HttpUrl`` is the first line of defense — it rejects non-http(s) schemes
    and malformed URLs before they ever reach the scanner.
    """

    url: HttpUrl = Field(..., description="The http(s) URL whose response headers will be analyzed.")


class HeaderFinding(BaseModel):
    """The graded result of checking one security header."""

    name: str
    status: CheckStatus
    present: bool
    value: str | None = None
    severity: str = Field(..., description="Relative importance: high, medium, or low.")
    points_awarded: int
    points_possible: int
    description: str = Field(..., description="What the header protects against.")
    recommendation: str = Field(..., description="Suggested value if missing or weak.")
    note: str | None = Field(default=None, description="Why a present header was only partially credited.")


class ScanResponse(BaseModel):
    """The full graded report for a scanned URL."""

    url: str
    final_url: str = Field(..., description="The URL actually scanned after following redirects.")
    status_code: int
    score: int = Field(..., ge=0, le=100)
    grade: str = Field(..., description="Letter grade derived from the score (A+ through F).")
    headers_present: int
    headers_missing: int
    findings: list[HeaderFinding]
    info_disclosure: dict[str, str] = Field(
        default_factory=dict,
        description="Headers that leak implementation details and should ideally be removed.",
    )
    scanned_at: str = Field(..., description="UTC timestamp (ISO 8601) of the scan.")
