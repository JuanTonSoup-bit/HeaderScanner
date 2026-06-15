"""Tests for the SSRF-safe fetcher, with the network fully mocked."""

import socket

import httpx
import pytest

from app.config import Settings
from app.scanner.fetch import FetchError, HeaderFetcher
from app.scanner.ssrf import SSRFError

PUBLIC_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def _public_dns(monkeypatch):
    """Map test hostnames to a public IP; IP literals pass through unchanged."""

    def fake_getaddrinfo(host, *args, **kwargs):
        public = {"example.com": PUBLIC_IP, "good.example": PUBLIC_IP}
        addr = public.get(host, host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (addr, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


def _fetcher(handler, **overrides) -> HeaderFetcher:
    settings = Settings(**overrides)
    transport = httpx.MockTransport(handler)
    return HeaderFetcher(
        settings,
        client_factory=lambda: httpx.AsyncClient(transport=transport, follow_redirects=False),
    )


async def test_fetch_returns_headers():
    def handler(request):
        return httpx.Response(200, headers={"X-Frame-Options": "DENY"})

    result = await _fetcher(handler).fetch("https://example.com/")
    assert result.status_code == 200
    assert result.final_url == "https://example.com/"
    assert result.headers["x-frame-options"] == "DENY"


async def test_fetch_connects_to_validated_ip():
    seen = {}

    def handler(request):
        seen["host"] = request.url.host
        return httpx.Response(200)

    await _fetcher(handler).fetch("https://example.com/")
    # The request is sent to the validated IP literal, not the hostname.
    assert seen["host"] == PUBLIC_IP


async def test_fetch_follows_redirects():
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "https://example.com/end"})
        return httpx.Response(200, headers={"Strict-Transport-Security": "max-age=63072000"})

    result = await _fetcher(handler).fetch("https://example.com/start")
    assert result.final_url == "https://example.com/end"
    assert result.status_code == 200


async def test_fetch_rejects_redirect_to_internal_address():
    def handler(request):
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})

    with pytest.raises(SSRFError, match="blocked address"):
        await _fetcher(handler).fetch("https://example.com/")


async def test_fetch_caps_redirects():
    def handler(request):
        return httpx.Response(302, headers={"Location": "https://example.com/loop"})

    with pytest.raises(FetchError, match="maximum"):
        await _fetcher(handler, max_redirects=2).fetch("https://example.com/")


async def test_fetch_wraps_network_errors():
    def handler(request):
        raise httpx.ConnectError("connection refused")

    with pytest.raises(FetchError, match="failed"):
        await _fetcher(handler).fetch("https://example.com/")
