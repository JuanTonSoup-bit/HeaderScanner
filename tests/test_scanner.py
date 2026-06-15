"""Unit tests for the pure grading logic and the SSRF guard."""

import pytest

from app.scanner import (
    SECURITY_HEADERS,
    ScanError,
    _grade,
    _is_safe_host,
    analyze_headers,
    scan_url,
)

ALL_SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}


def _analyze(headers):
    return analyze_headers(
        url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        headers=headers,
    )


def test_all_headers_present_scores_perfect():
    result = _analyze(ALL_SECURE_HEADERS)
    assert result.score == 100
    assert result.grade == "A+"
    assert result.headers_present == len(SECURITY_HEADERS)
    assert result.headers_missing == 0


def test_no_headers_present_fails():
    result = _analyze({})
    assert result.score == 0
    assert result.grade == "F"
    assert result.headers_present == 0
    assert result.headers_missing == len(SECURITY_HEADERS)


def test_header_lookup_is_case_insensitive():
    result = _analyze({"strict-transport-security": "max-age=600"})
    hsts = next(f for f in result.findings if f.name == "Strict-Transport-Security")
    assert hsts.present is True
    assert hsts.value == "max-age=600"


def test_missing_high_severity_headers_drop_score():
    headers = dict(ALL_SECURE_HEADERS)
    del headers["Content-Security-Policy"]
    del headers["Strict-Transport-Security"]
    result = _analyze(headers)
    # The two high-severity headers are worth 40 of 76 points.
    assert result.score == round((76 - 40) / 76 * 100)
    assert result.grade == "F"


def test_info_disclosure_is_detected_and_penalized():
    headers = dict(ALL_SECURE_HEADERS)
    headers["Server"] = "Apache/2.4.41"
    headers["X-Powered-By"] = "PHP/8.1"
    result = _analyze(headers)
    assert result.info_disclosure == {"Server": "Apache/2.4.41", "X-Powered-By": "PHP/8.1"}
    # Perfect 100, minus 5 points per disclosed header.
    assert result.score == 90


@pytest.mark.parametrize(
    ("score", "expected"),
    [(100, "A+"), (95, "A+"), (92, "A"), (85, "B"), (72, "C"), (61, "D"), (40, "F"), (0, "F")],
)
def test_grade_boundaries(score, expected):
    assert _grade(score) == expected


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "169.254.169.254", "10.0.0.5", "0.0.0.0"])
def test_ssrf_guard_rejects_internal_hosts(host):
    assert _is_safe_host(host) is False


async def test_scan_url_rejects_non_http_scheme():
    with pytest.raises(ScanError, match="http or https"):
        await scan_url("ftp://example.com")


async def test_scan_url_blocks_private_target_by_default():
    with pytest.raises(ScanError, match="private, loopback, or reserved"):
        await scan_url("http://127.0.0.1:8000")
