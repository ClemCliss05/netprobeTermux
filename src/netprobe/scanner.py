"""TCP port scanning utilities."""

import errno
import socket
import time
from dataclasses import dataclass
from enum import Enum


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
    error_code: int | None = None


def scan_port(
    host: str,
    port: int,
    timeout: float = 1.0,
) -> PortScanResult:
    """Attempt to establish a TCP connection to a host and port."""

    if not host:
        raise ValueError("Host cannot be empty")

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")

    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero")

    start_time = time.perf_counter()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            error_code = sock.connect_ex((host, port))

        latency_ms = (time.perf_counter() - start_time) * 1000

    except OSError as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000

        return PortScanResult(
            host=host,
            port=port,
            state=PortState.ERROR,
            latency_ms=latency_ms,
            error_code=exc.errno,
        )

    if error_code == 0:
        state = PortState.OPEN
    elif error_code == errno.ECONNREFUSED:
        state = PortState.CLOSED
    elif error_code == errno.ETIMEDOUT:
        state = PortState.NO_RESPONSE
    else:
        state = PortState.ERROR

    return PortScanResult(
        host=host,
        port=port,
        state=state,
        latency_ms=latency_ms,
        error_code=error_code if error_code != 0 else None,
    )

