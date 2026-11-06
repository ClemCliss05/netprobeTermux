
"""DNS lookup utilities."""

import socket
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class DNSLookupResult:
    """Result of a DNS lookup."""

    host: str
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    latency_ms: float
    error: str | None = None
    error_code: int | None = None


def lookup_host(host: str) -> DNSLookupResult:
    """Resolve a hostname into IPv4 and IPv6 addresses."""

    if not isinstance(host, str) or not host.strip():
        raise ValueError("Host must be a non-empty string")

    start_time = time.perf_counter()

    try:
        addresses = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )

    except socket.gaierror as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000

        return DNSLookupResult(
            host=host,
            ipv4=(),
            ipv6=(),
            latency_ms=latency_ms,
            error=str(exc),
            error_code=exc.errno,
        )

    ipv4 = set()
    ipv6 = set()

    for family, _, _, _, sockaddr in addresses:
        if family == socket.AF_INET:
            ipv4.add(sockaddr[0])

        elif family == socket.AF_INET6:
            ipv6.add(sockaddr[0])

    latency_ms = (time.perf_counter() - start_time) * 1000

    return DNSLookupResult(
        host=host,
        ipv4=tuple(sorted(ipv4)),
        ipv6=tuple(sorted(ipv6)),
        latency_ms=latency_ms,
    )

