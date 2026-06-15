"""Table-driven unit tests for the pure scoring logic."""

import pytest

from app.models.schemas import CheckStatus
from app.scoring.grader import grade_headers, letter_grade
from app.scoring.rubric import RULES

ALL_STRONG = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}


def test_all_strong_headers_score_perfect():
    result = grade_headers(ALL_STRONG)
    assert result.score == 100
    assert result.grade == "A+"
    assert result.headers_present == len(RULES)
    assert result.headers_missing == 0
    assert all(f.status is CheckStatus.PASS for f in result.findings)


def test_no_headers_fail():
    result = grade_headers({})
    assert result.score == 0
    assert result.grade == "F"
    assert result.headers_missing == len(RULES)
    assert all(f.status is CheckStatus.FAIL for f in result.findings)


def test_lookup_is_case_insensitive():
    result = grade_headers({"strict-transport-security": "max-age=63072000"})
    hsts = next(f for f in result.findings if f.name == "Strict-Transport-Security")
    assert hsts.present is True
    assert hsts.status is CheckStatus.PASS


@pytest.mark.parametrize(
    ("value", "expected_status"),
    [
        ("max-age=63072000", CheckStatus.PASS),
        ("max-age=100", CheckStatus.WARN),  # below the 180-day minimum
        ("includeSubDomains", CheckStatus.WARN),  # no max-age at all
    ],
)
def test_hsts_value_strength(value, expected_status):
    finding = next(
        f
        for f in grade_headers({"Strict-Transport-Security": value}).findings
        if f.name == "Strict-Transport-Security"
    )
    assert finding.status is expected_status
    if expected_status is CheckStatus.WARN:
        assert finding.note is not None
        assert finding.points_awarded < finding.points_possible


@pytest.mark.parametrize(
    ("value", "expected_status"),
    [
        ("default-src 'self'", CheckStatus.PASS),
        ("default-src 'self' 'unsafe-inline'", CheckStatus.WARN),
        ("script-src 'unsafe-eval'", CheckStatus.WARN),
    ],
)
def test_csp_unsafe_directives_warn(value, expected_status):
    finding = next(
        f
        for f in grade_headers({"Content-Security-Policy": value}).findings
        if f.name == "Content-Security-Policy"
    )
    assert finding.status is expected_status


@pytest.mark.parametrize(
    ("value", "expected_status"),
    [("DENY", CheckStatus.PASS), ("SAMEORIGIN", CheckStatus.PASS), ("ALLOW-FROM x", CheckStatus.WARN)],
)
def test_x_frame_options_values(value, expected_status):
    finding = next(
        f for f in grade_headers({"X-Frame-Options": value}).findings if f.name == "X-Frame-Options"
    )
    assert finding.status is expected_status


def test_info_disclosure_detected_and_penalized():
    headers = dict(ALL_STRONG)
    headers["Server"] = "Apache/2.4.41"
    headers["X-Powered-By"] = "PHP/8.1"
    result = grade_headers(headers)
    assert result.info_disclosure == {"Server": "Apache/2.4.41", "X-Powered-By": "PHP/8.1"}
    assert result.score == 90  # 100 minus 5 per disclosed header


@pytest.mark.parametrize(
    ("score", "expected"),
    [(100, "A+"), (95, "A+"), (92, "A"), (85, "B"), (72, "C"), (61, "D"), (40, "F"), (0, "F")],
)
def test_letter_grade_boundaries(score, expected):
    assert letter_grade(score) == expected
