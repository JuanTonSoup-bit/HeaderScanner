"""Pydantic models describing the scanner's request and response shapes."""

from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl


class ScanRequest(BaseModel):
    """Incoming request: a single URL to inspect."""

    url: HttpUrl = Field(..., description="The http(s) URL whose response headers will be analyzed.")


class HeaderFinding(BaseModel):
    """The result of checking a single security header."""

    name: str
    present: bool
    value: str | None = None
    severity: str = Field(..., description="Relative importance: high, medium, or low.")
    description: str = Field(..., description="What the header protects against.")
    recommendation: str = Field(..., description="Suggested value if the header is missing.")


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
