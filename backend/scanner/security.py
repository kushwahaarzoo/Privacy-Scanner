import ipaddress
import os
import socket
from urllib.parse import urlparse


def assert_public_url(url: str) -> None:
    """Reject non-http(s), credentials, and private/internal targets."""
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("A valid HTTP or HTTPS URL is required.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")

    # Set ALLOW_PRIVATE_TARGETS=1 only when testing your own local site.
    if os.getenv("ALLOW_PRIVATE_TARGETS") == "1":
        return

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        infos = socket.getaddrinfo(
            parsed.hostname, port, proto=socket.IPPROTO_TCP
        )
    except socket.gaierror:
        raise ValueError("Hostname could not be resolved.")

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified
        ):
            raise ValueError("Target resolves to a non-public address.")