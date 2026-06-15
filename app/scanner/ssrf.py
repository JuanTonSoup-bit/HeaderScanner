"""SSRF protection.

The API fetches arbitrary user-supplied URLs, which is a textbook
server-side-request-forgery sink. These helpers enforce, in layers:

* an http/https scheme allowlist;
* rejection of private, loopback, link-local, reserved, multicast, and
  unspecified addresses (IPv4 and IPv6);
* an explicit block on the cloud metadata endpoint 169.254.169.254;
* validation of the *resolved IP addresses*, so the caller can connect to a
  vetted IP rather than re-resolving the hostname (closing the DNS-rebinding
  window). See :mod:`app.scanner.fetch`.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}

# Explicitly blocked literals. 169.254.169.254 is already link-local, but the
# cloud metadata endpoint is the single most-abused SSRF target, so it is
# called out by name (and covered by a dedicated test).
BLOCKED_LITERALS = frozenset({"169.254.169.254", "fd00:ec2::254"})


class SSRFError(Exception):
    """Raised when a URL or resolved address is not allowed to be fetched."""


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_url(url: str) -> tuple[str, str, int]:
    """Validate the scheme and structure of ``url``.

    Returns ``(scheme, hostname, port)``. Raises :class:`SSRFError` on a
    disallowed scheme or a missing hostname.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFError("URL must use the http or https scheme.")
    if not parsed.hostname:
        raise SSRFError("URL is missing a hostname.")
    port = parsed.port or DEFAULT_PORTS[parsed.scheme]
    return parsed.scheme, parsed.hostname, port


def resolve_safe_ips(host: str) -> list[str]:
    """Resolve ``host`` and return its addresses, or raise :class:`SSRFError`.

    *Every* resolved address must be publicly routable; if any maps to an
    internal range the whole host is rejected (so an attacker cannot smuggle an
    internal address alongside a public one).
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SSRFError(f"Could not resolve host: {host}") from exc

    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0])
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise SSRFError(f"Resolved an invalid address for {host}.") from exc
        if address in BLOCKED_LITERALS or _ip_is_blocked(ip):
            raise SSRFError(f"Refusing to connect to blocked address {address} (host {host}).")
        addresses.append(address)

    if not addresses:
        raise SSRFError(f"No addresses resolved for {host}.")
    return addresses
