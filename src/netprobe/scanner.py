
"""TCP port scanning utilities."""

import errno
import socket
import time
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum


def _validate_host(host: str) -> None:
    """Validate the target hostname or IP address."""

    if not isinstance(host, str) or not host.strip():
        raise ValueError("Host must be a non-empty string")


def _validate_timeout(timeout: float) -> None:
    """Validate the connection timeout."""

    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("Timeout must be a number")

    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero")


def _validate_port(port: int) -> None:
    """Validate a TCP port number."""

    if type(port) is not int:
        raise ValueError("Port must be an integer")

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")


class PortState(str, Enum):
    """Possible outcomes of a TCP connection attempt."""

    OPEN = "open"
    CLOSED = "closed"
    NO_RESPONSE = "no_response"
    ERROR = "error"


@dataclass(frozen=True)
class PortScanResult:
    """Result of a TCP port scan."""

    host: str
    port: int
    state: PortState
    latency_ms: float
    address: str | None = None
    family: socket.AddressFamily | None = None
    error_code: int | None = None


def scan_port(
    host: str,
    port: int,
    timeout: float = 1.0,
) -> list[PortScanResult]:
    """Scan a TCP port on every resolved IP address."""

    _validate_host(host)
    _validate_port(port)
    _validate_timeout(timeout)

    try:
        addresses = socket.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        return [
            PortScanResult(
                host=host,
                port=port,
                state=PortState.ERROR,
                latency_ms=0.0,
                error_code=exc.errno,
            )
        ]

    results = []
    seen_addresses = set()

    for family, socktype, proto, _, sockaddr in addresses:
        address = sockaddr[0]
        address_key = (family, socktype, proto, sockaddr)

        if address_key in seen_addresses:
            continue

        seen_addresses.add(address_key)
        start_time = time.perf_counter()

        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                error_code = sock.connect_ex(sockaddr)

        except OSError as exc:
            error_code = exc.errno
            state = PortState.ERROR

        else:
            if error_code == 0:
                state = PortState.OPEN
            elif error_code == errno.ECONNREFUSED:
                state = PortState.CLOSED
            elif error_code == errno.ETIMEDOUT:
                state = PortState.NO_RESPONSE
            else:
                state = PortState.ERROR

        latency_ms = (time.perf_counter() - start_time) * 1000

        results.append(
            PortScanResult(
                host=host,
                port=port,
                state=state,
                latency_ms=latency_ms,
                address=address,
                family=family,
                error_code=error_code if error_code != 0 else None,
            )
        )

    if not results:
        results.append(
            PortScanResult(
                host=host,
                port=port,
                state=PortState.ERROR,
                latency_ms=0.0,
            )
        )

    return results


def scan_ports(
    host: str,
    ports: Iterable[int],
    timeout: float = 1.0,
) -> list[PortScanResult]:
    """Scan multiple TCP ports sequentially."""

    _validate_host(host)
    _validate_timeout(timeout)

    try:
        port_list = list(ports)
    except TypeError as exc:
        raise ValueError("Ports must be an iterable of integers") from exc

    for port in port_list:
        _validate_port(port)

    results = []

    for port in port_list:
        results.extend(scan_port(host, port, timeout))

    return results

