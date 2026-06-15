"""SSRF-safe HTTP header fetching.

:class:`HeaderFetcher` performs the outbound request with several protections:

* the HTTP client is injectable, so tests never touch the network;
* automatic redirects are disabled and followed manually, re-validating the
  target of every hop (a redirect to ``http://169.254.169.254/`` is rejected);
* the hostname is resolved and validated, then the request connects to the
  vetted IP literal while preserving the ``Host`` header and TLS SNI — so the
  IP we validate is the IP we connect to, closing the DNS-rebinding window;
* a hard timeout and redirect cap bound the work, and only response headers are
  read (the body is never downloaded).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from app.config import Settings
from app.scanner.ssrf import resolve_safe_ips, validate_url

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class FetchError(Exception):
    """Raised when a target cannot be fetched (network failure, too many redirects)."""


@dataclass
class FetchResult:
    """The minimal response data the scanner needs: headers plus metadata."""

    final_url: str
    status_code: int
    headers: dict[str, str]


def _connect_url(scheme: str, ip: str, port: int, path_and_query: str) -> str:
    host = f"[{ip}]" if ":" in ip else ip
    return f"{scheme}://{host}:{port}{path_and_query}"


def _host_header(host: str, port: int) -> str:
    return host if port in (80, 443) else f"{host}:{port}"


class HeaderFetcher:
    """Fetches response headers for a URL with SSRF protections applied."""

    def __init__(
        self,
        settings: Settings,
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
    ) -> None:
        self._settings = settings
        self._client_factory = client_factory or self._default_client

    def _default_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self._settings.request_timeout,
            follow_redirects=False,
            headers={"User-Agent": self._settings.user_agent},
        )

    async def fetch(self, url: str) -> FetchResult:
        """Resolve, validate, and fetch ``url``, following redirects safely."""
        current = url
        allow_private = self._settings.allow_private_targets

        async with self._client_factory() as client:
            for _ in range(self._settings.max_redirects + 1):
                scheme, host, port = validate_url(current)

                if allow_private:
                    # Trust the client's own resolution (used only for local testing).
                    request = client.build_request("GET", current)
                else:
                    ip = resolve_safe_ips(host)[0]
                    parsed = urlparse(current)
                    path_and_query = parsed.path or "/"
                    if parsed.query:
                        path_and_query = f"{path_and_query}?{parsed.query}"
                    request = client.build_request(
                        "GET",
                        _connect_url(scheme, ip, port, path_and_query),
                        headers={"Host": _host_header(host, port)},
                        extensions={"sni_hostname": host},
                    )

                try:
                    response = await client.send(request, stream=True)
                except httpx.RequestError as exc:
                    raise FetchError(f"Request to {host} failed: {exc}") from exc

                location = response.headers.get("location")
                status_code = response.status_code
                headers = dict(response.headers)
                await response.aclose()

                if status_code in REDIRECT_STATUSES and location:
                    current = urljoin(current, location)
                    continue

                return FetchResult(final_url=current, status_code=status_code, headers=headers)

        raise FetchError(f"Exceeded the maximum of {self._settings.max_redirects} redirects.")
