"""Tests proving the SSRF guard blocks internal and malformed targets."""

import socket

import pytest

from app.scanner.ssrf import SSRFError, resolve_safe_ips, validate_url


@pytest.mark.parametrize("url", ["ftp://example.com", "file:///etc/passwd", "gopher://example.com"])
def test_validate_url_rejects_non_http_schemes(url):
    with pytest.raises(SSRFError, match="http or https"):
        validate_url(url)


def test_validate_url_returns_scheme_host_port():
    assert validate_url("https://example.com/path") == ("https", "example.com", 443)
    assert validate_url("http://example.com:8080/") == ("http", "example.com", 8080)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",  # loopback
        "10.0.0.5",  # private
        "192.168.1.10",  # private
        "172.16.5.5",  # private
        "169.254.0.1",  # link-local
        "169.254.169.254",  # cloud metadata endpoint
        "0.0.0.0",  # unspecified
        "::1",  # IPv6 loopback
        "fe80::1",  # IPv6 link-local
        "fc00::1",  # IPv6 unique-local
    ],
)
def test_resolve_safe_ips_blocks_internal_addresses(address):
    # IP literals resolve to themselves without any network access.
    with pytest.raises(SSRFError, match="blocked address"):
        resolve_safe_ips(address)


def test_resolve_safe_ips_allows_public_address(monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert resolve_safe_ips("example.com") == ["93.184.216.34"]


def test_resolve_safe_ips_rejects_host_with_any_internal_address(monkeypatch):
    # A host that resolves to both a public and a private address is rejected.
    def fake_getaddrinfo(host, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(SSRFError, match="blocked address"):
        resolve_safe_ips("rebind.example.com")


def test_resolve_safe_ips_handles_resolution_failure(monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(SSRFError, match="Could not resolve"):
        resolve_safe_ips("does-not-exist.invalid")
