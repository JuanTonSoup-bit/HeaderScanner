"""Core security-header analysis logic.

The network fetch (:func:`scan_url`) and the grading (:func:`analyze_headers`)
are intentionally kept separate so the scoring logic can be unit-tested without
making real HTTP requests.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from .models import HeaderFinding, ScanResponse

USER_AGENT = "SecurityHeaderScanner/1.0 (+https://github.com/JuanTonSoup-bit/security-header-scanner)"
REQUEST_TIMEOUT = 10.0

# Points awarded when a header in a given severity tier is present.
SEVERITY_WEIGHTS: dict[str, int] = {
    "high": 20,
    "medium": 12,
    "low": 6,
}


@dataclass(frozen=True)
class HeaderCheck:
    """Definition of a single security header we grade."""

    name: str
    severity: str
    description: str
    recommendation: str


# The headers we grade, ordered roughly by importance.
SECURITY_HEADERS: tuple[HeaderCheck, ...] = (
    HeaderCheck(
        name="Strict-Transport-Security",
        severity="high",
        description="Forces browsers to use HTTPS, preventing protocol-downgrade and cookie-hijacking.",
        recommendation="Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    HeaderCheck(
        name="Content-Security-Policy",
        severity="high",
        description="Mitigates cross-site scripting (XSS) and injection by restricting content sources.",
        recommendation="Content-Security-Policy: default-src 'self'",
    ),
    HeaderCheck(
        name="X-Frame-Options",
        severity="medium",
        description="Protects against clickjacking by controlling whether the page may be framed.",
        recommendation="X-Frame-Options: DENY",
    ),
    HeaderCheck(
        name="X-Content-Type-Options",
        severity="medium",
        description="Stops browsers from MIME-sniffing a response away from its declared content type.",
        recommendation="X-Content-Type-Options: nosniff",
    ),
    HeaderCheck(
        name="Referrer-Policy",
        severity="low",
        description="Controls how much referrer information is sent with requests, limiting data leakage.",
        recommendation="Referrer-Policy: strict-origin-when-cross-origin",
    ),
    HeaderCheck(
        name="Permissions-Policy",
        severity="low",
        description="Restricts which browser features (camera, geolocation, etc.) the site may use.",
        recommendation="Permissions-Policy: geolocation=(), camera=(), microphone=()",
    ),
)

# Response headers that disclose implementation details and should ideally be removed.
INFO_DISCLOSURE_HEADERS: tuple[str, ...] = ("Server", "X-Powered-By", "X-AspNet-Version")

# Each information-disclosure header found subtracts this many points.
INFO_DISCLOSURE_PENALTY = 5


class ScanError(Exception):
    """Raised when a URL cannot be scanned (bad input, blocked target, network failure)."""


def _grade(score: int) -> str:
    """Map a 0-100 score to a letter grade."""
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _is_safe_host(hostname: str) -> bool:
    """Return ``True`` only if every resolved address is publicly routable.

    This is a basic SSRF guard: it prevents the scanner from being pointed at
    loopback, private, link-local, or otherwise reserved addresses on the host
    network.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
    return True


def analyze_headers(
    *,
    url: str,
    final_url: str,
    status_code: int,
    headers: Mapping[str, str],
) -> ScanResponse:
    """Grade a set of response headers. Pure function — no network access."""
    normalized = {key.lower(): value for key, value in headers.items()}

    findings: list[HeaderFinding] = []
    earned = 0
    present_count = 0
    total = sum(SEVERITY_WEIGHTS[check.severity] for check in SECURITY_HEADERS)

    for check in SECURITY_HEADERS:
        value = normalized.get(check.name.lower())
        present = value is not None
        if present:
            earned += SEVERITY_WEIGHTS[check.severity]
            present_count += 1
        findings.append(
            HeaderFinding(
                name=check.name,
                present=present,
                value=value,
                severity=check.severity,
                description=check.description,
                recommendation=check.recommendation,
            )
        )

    info_disclosure = {
        name: normalized[name.lower()] for name in INFO_DISCLOSURE_HEADERS if name.lower() in normalized
    }

    score = round(earned / total * 100) if total else 0
    score = max(0, score - INFO_DISCLOSURE_PENALTY * len(info_disclosure))

    return ScanResponse(
        url=url,
        final_url=final_url,
        status_code=status_code,
        score=score,
        grade=_grade(score),
        headers_present=present_count,
        headers_missing=len(SECURITY_HEADERS) - present_count,
        findings=findings,
        info_disclosure=info_disclosure,
        scanned_at=datetime.now(UTC).isoformat(),
    )


async def scan_url(url: str, *, allow_private: bool | None = None) -> ScanResponse:
    """Fetch ``url`` and return a graded :class:`ScanResponse`.

    Raises :class:`ScanError` on invalid input, blocked targets, or network failures.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ScanError("URL must use the http or https scheme.")
    if not parsed.hostname:
        raise ScanError("URL is missing a hostname.")

    if allow_private is None:
        allow_private = os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() == "true"
    if not allow_private and not _is_safe_host(parsed.hostname):
        raise ScanError("Refusing to scan a private, loopback, or reserved address.")

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        try:
            response = await client.get(url)
        except httpx.RequestError as exc:
            raise ScanError(f"Request to {url} failed: {exc}") from exc

    return analyze_headers(
        url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        headers=response.headers,
    )
