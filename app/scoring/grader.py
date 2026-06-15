"""Pure grading: turn a set of response headers into a graded report.

No network access and no framework imports, so this is trivially unit-testable.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from app.models.schemas import CheckStatus, HeaderFinding
from app.scoring.rubric import (
    INFO_DISCLOSURE_HEADERS,
    INFO_DISCLOSURE_PENALTY,
    RULES,
)


@dataclass
class GradeResult:
    """The graded outcome, independent of any HTTP metadata."""

    findings: list[HeaderFinding]
    score: int
    grade: str
    headers_present: int
    headers_missing: int
    info_disclosure: dict[str, str]


def letter_grade(score: int) -> str:
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


def grade_headers(headers: Mapping[str, str]) -> GradeResult:
    """Grade a set of response headers against the rubric."""
    normalized = {key.lower(): value for key, value in headers.items()}

    findings: list[HeaderFinding] = []
    earned = 0
    possible = 0
    present_count = 0

    for rule in RULES:
        possible += rule.points_possible
        value = normalized.get(rule.name.lower())

        if value is None:
            findings.append(
                HeaderFinding(
                    name=rule.name,
                    status=CheckStatus.FAIL,
                    present=False,
                    value=None,
                    severity=rule.severity,
                    points_awarded=0,
                    points_possible=rule.points_possible,
                    description=rule.description,
                    recommendation=rule.recommendation,
                    note=None,
                )
            )
            continue

        present_count += 1
        status, fraction, note = rule.evaluate(value)
        awarded = round(rule.points_possible * fraction)
        earned += awarded
        findings.append(
            HeaderFinding(
                name=rule.name,
                status=status,
                present=True,
                value=value,
                severity=rule.severity,
                points_awarded=awarded,
                points_possible=rule.points_possible,
                description=rule.description,
                recommendation=rule.recommendation,
                note=note,
            )
        )

    info_disclosure = {
        name: normalized[name.lower()] for name in INFO_DISCLOSURE_HEADERS if name.lower() in normalized
    }

    score = round(earned / possible * 100) if possible else 0
    score = max(0, score - INFO_DISCLOSURE_PENALTY * len(info_disclosure))

    return GradeResult(
        findings=findings,
        score=score,
        grade=letter_grade(score),
        headers_present=present_count,
        headers_missing=len(RULES) - present_count,
        info_disclosure=info_disclosure,
    )
