"""The grading rubric.

Each security header has a severity (which sets its maximum points) and an
``evaluate`` function that judges the *value*, not just its presence. An
evaluator returns ``(status, fraction, note)`` where ``fraction`` is the share
of the header's points to award (1.0 = full credit, 0.5 = partial).

This module is the single documented source of truth for *why* a site gets a
given grade.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from app.models.schemas import CheckStatus

# Maximum points per header, by severity tier. The totals (high*2 + medium*2 +
# low*2 = 76) are normalized to a 0-100 score in the grader.
SEVERITY_POINTS: dict[str, int] = {
    "high": 20,
    "medium": 12,
    "low": 6,
}

# Recommended minimum HSTS lifetime: 180 days, matching hstspreload.org.
HSTS_MIN_MAX_AGE = 15_552_000

# Response headers that disclose implementation details and should be removed.
INFO_DISCLOSURE_HEADERS: tuple[str, ...] = ("Server", "X-Powered-By", "X-AspNet-Version")

# Points subtracted per information-disclosure header found.
INFO_DISCLOSURE_PENALTY = 5

Evaluator = Callable[[str], "tuple[CheckStatus, float, str | None]"]


def _hsts_max_age(value: str) -> int | None:
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _eval_hsts(value: str) -> tuple[CheckStatus, float, str | None]:
    age = _hsts_max_age(value)
    if age is None:
        return CheckStatus.WARN, 0.5, "No max-age directive found."
    if age < HSTS_MIN_MAX_AGE:
        return CheckStatus.WARN, 0.5, f"max-age is {age}s; recommend at least {HSTS_MIN_MAX_AGE}s (180 days)."
    return CheckStatus.PASS, 1.0, None


def _eval_csp(value: str) -> tuple[CheckStatus, float, str | None]:
    lowered = value.lower()
    if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
        return CheckStatus.WARN, 0.5, "Policy allows 'unsafe-inline'/'unsafe-eval', weakening XSS protection."
    return CheckStatus.PASS, 1.0, None


def _eval_x_frame_options(value: str) -> tuple[CheckStatus, float, str | None]:
    if value.strip().upper() in {"DENY", "SAMEORIGIN"}:
        return CheckStatus.PASS, 1.0, None
    return CheckStatus.WARN, 0.5, "Use DENY or SAMEORIGIN."


def _eval_x_content_type_options(value: str) -> tuple[CheckStatus, float, str | None]:
    if value.strip().lower() == "nosniff":
        return CheckStatus.PASS, 1.0, None
    return CheckStatus.WARN, 0.5, "Expected the value 'nosniff'."


def _eval_referrer_policy(value: str) -> tuple[CheckStatus, float, str | None]:
    if value.strip().lower() == "unsafe-url":
        return CheckStatus.WARN, 0.5, "'unsafe-url' leaks full URLs to other origins."
    return CheckStatus.PASS, 1.0, None


def _eval_present(_value: str) -> tuple[CheckStatus, float, str | None]:
    return CheckStatus.PASS, 1.0, None


@dataclass(frozen=True)
class HeaderRule:
    """A single header we grade."""

    name: str
    severity: str
    description: str
    recommendation: str
    evaluate: Evaluator

    @property
    def points_possible(self) -> int:
        return SEVERITY_POINTS[self.severity]


RULES: tuple[HeaderRule, ...] = (
    HeaderRule(
        name="Strict-Transport-Security",
        severity="high",
        description="Forces browsers to use HTTPS, preventing protocol-downgrade and cookie-hijacking.",
        recommendation="Strict-Transport-Security: max-age=31536000; includeSubDomains",
        evaluate=_eval_hsts,
    ),
    HeaderRule(
        name="Content-Security-Policy",
        severity="high",
        description="Mitigates cross-site scripting (XSS) and injection by restricting content sources.",
        recommendation="Content-Security-Policy: default-src 'self'",
        evaluate=_eval_csp,
    ),
    HeaderRule(
        name="X-Frame-Options",
        severity="medium",
        description="Protects against clickjacking by controlling whether the page may be framed.",
        recommendation="X-Frame-Options: DENY",
        evaluate=_eval_x_frame_options,
    ),
    HeaderRule(
        name="X-Content-Type-Options",
        severity="medium",
        description="Stops browsers from MIME-sniffing a response away from its declared content type.",
        recommendation="X-Content-Type-Options: nosniff",
        evaluate=_eval_x_content_type_options,
    ),
    HeaderRule(
        name="Referrer-Policy",
        severity="low",
        description="Controls how much referrer information is sent with requests, limiting data leakage.",
        recommendation="Referrer-Policy: strict-origin-when-cross-origin",
        evaluate=_eval_referrer_policy,
    ),
    HeaderRule(
        name="Permissions-Policy",
        severity="low",
        description="Restricts which browser features (camera, geolocation, etc.) the site may use.",
        recommendation="Permissions-Policy: geolocation=(), camera=(), microphone=()",
        evaluate=_eval_present,
    ),
)
