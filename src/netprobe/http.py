"""HTTP diagnostic utilities."""

import time
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class HTTPResult:
    """Result of an HTTP request."""

    url: str
    status_code: int | None
    reason: str | None
    final_url: str | None
    latency_ms: float
    content_type: str | None
    error: str | None = None


def check_http(url: str, timeout: float = 5.0) -> HTTPResult:
    """Send an HTTP GET request and return diagnostic information."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string")

    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        raise ValueError("Timeout must be a positive number")

    if timeout <= 0:
        raise ValueError("Timeout must be a positive number")

    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "NetProbe/0.1"},
        method="GET",
    )

    start_time = time.perf_counter()

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            latency_ms = (time.perf_counter() - start_time) * 1000

            return HTTPResult(
                url=url,
                status_code=response.status,
                reason=response.reason,
                final_url=response.url,
                latency_ms=latency_ms,
                content_type=response.headers.get("Content-Type"),
            )

    except urllib.error.HTTPError as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000

        return HTTPResult(
            url=url,
            status_code=exc.code,
            reason=exc.reason,
            final_url=exc.url,
            latency_ms=latency_ms,
            content_type=exc.headers.get("Content-Type"),
        )

    except (urllib.error.URLError, OSError, ValueError) as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000

        return HTTPResult(
            url=url,
            status_code=None,
            reason=None,
            final_url=None,
            latency_ms=latency_ms,
            content_type=None,
            error=str(exc.reason if isinstance(exc, urllib.error.URLError) else exc),
        )
