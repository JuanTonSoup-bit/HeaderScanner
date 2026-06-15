"""API tests using FastAPI's TestClient, with the fetcher injected via DI."""

import pytest
from fastapi.testclient import TestClient

from app.api.routes import get_fetcher
from app.main import app
from app.scanner.fetch import FetchError, FetchResult
from app.scanner.ssrf import SSRFError

client = TestClient(app)


class FakeFetcher:
    """Stand-in fetcher: returns canned headers or raises, never hits the network."""

    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error

    async def fetch(self, url):
        if self._error is not None:
            raise self._error
        return self._result


def _use_fetcher(fetcher):
    app.dependency_overrides[get_fetcher] = lambda: fetcher


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_dashboard_served_at_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "Security Header Scanner" in response.text


def test_scan_happy_path():
    _use_fetcher(
        FakeFetcher(
            result=FetchResult(
                final_url="https://example.com/",
                status_code=200,
                headers={"Strict-Transport-Security": "max-age=63072000", "X-Frame-Options": "DENY"},
            )
        )
    )
    response = client.post("/api/scan", json={"url": "https://example.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["grade"]
    assert body["headers_present"] == 2
    assert len(body["findings"]) == 6


def test_scan_rejects_invalid_url():
    response = client.post("/api/scan", json={"url": "not-a-url"})
    assert response.status_code == 422


def test_scan_rejects_non_http_scheme():
    response = client.post("/api/scan", json={"url": "ftp://example.com"})
    assert response.status_code == 422


def test_scan_maps_ssrf_error_to_400():
    _use_fetcher(FakeFetcher(error=SSRFError("Refusing to connect to blocked address 127.0.0.1.")))
    response = client.post("/api/scan", json={"url": "http://example.com"})
    assert response.status_code == 400
    assert "blocked address" in response.json()["detail"]


def test_scan_maps_fetch_error_to_400():
    _use_fetcher(FakeFetcher(error=FetchError("Request to example.com failed: timeout")))
    response = client.post("/api/scan", json={"url": "http://example.com"})
    assert response.status_code == 400
    assert "failed" in response.json()["detail"]
