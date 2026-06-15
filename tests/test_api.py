"""API tests using FastAPI's TestClient with the network layer mocked out."""

from fastapi.testclient import TestClient

from app import main
from app.main import app
from app.scanner import ScanError, analyze_headers

client = TestClient(app)


def _fake_response():
    return analyze_headers(
        url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
        },
    )


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_dashboard_is_served_at_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "Security Header Scanner" in response.text


def test_scan_happy_path(monkeypatch):
    async def fake_scan(url, **kwargs):
        return _fake_response()

    monkeypatch.setattr(main, "scan_url", fake_scan)

    response = client.post("/api/scan", json={"url": "https://example.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["grade"]
    assert body["headers_present"] == 2
    assert len(body["findings"]) == 6


def test_scan_rejects_invalid_url():
    response = client.post("/api/scan", json={"url": "not-a-url"})
    assert response.status_code == 422


def test_scan_surfaces_scan_error_as_400(monkeypatch):
    async def fake_scan(url, **kwargs):
        raise ScanError("Refusing to scan a private, loopback, or reserved address.")

    monkeypatch.setattr(main, "scan_url", fake_scan)

    response = client.post("/api/scan", json={"url": "http://example.com"})
    assert response.status_code == 400
    assert "Refusing to scan" in response.json()["detail"]
