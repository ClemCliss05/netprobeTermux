
"""TLS diagnostic utilities."""

import math
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class TLSResult:
    """Result of a TLS connection diagnostic."""

    host: str
    port: int
    tls_version: str | None
    cipher: str | None
    cipher_bits: int | None
    certificate_subject: str | None
    certificate_issuer: str | None
    not_before: str | None
    not_after: str | None
    days_remaining: int | None
    latency_ms: float
    error: str | None = None
    error_code: int | None = None


def _validate_inputs(host: str, port: int, timeout: float) -> None:
    """Validate TLS connection parameters."""

    if not isinstance(host, str) or not host.strip():
        raise ValueError("Host must be a non-empty string")

    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError("Port must be an integer")

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")

    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Timeout must be a positive finite number")


def _format_certificate_name(name: tuple) -> str | None:
    """Format a certificate subject or issuer."""

    parts = []

    for relative_name in name:
        for key, value in relative_name:
            parts.append(f"{key}={value}")

    return ", ".join(parts) if parts else None


def _format_certificate_date(value: str | None) -> str | None:
    """Convert a certificate date into ISO 8601 format."""

    if not value:
        return None

    timestamp = ssl.cert_time_to_seconds(value)

    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc,
    ).isoformat()


def check_tls(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
) -> TLSResult:
    """Establish a verified TLS connection and inspect its certificate."""

    _validate_inputs(host, port, timeout)

    start_time = time.perf_counter()

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=host,
            ) as tls_socket:

                certificate = tls_socket.getpeercert()

                cipher_info = tls_socket.cipher()

                not_before = certificate.get("notBefore")
                not_after = certificate.get("notAfter")

                expiry_timestamp = (
                    ssl.cert_time_to_seconds(not_after)
                    if not_after
                    else None
                )

                days_remaining = (
                    int((expiry_timestamp - time.time()) // 86400)
                    if expiry_timestamp is not None
                    else None
                )

                latency_ms = (
                    time.perf_counter() - start_time
                ) * 1000

                return TLSResult(
                    host=host,
                    port=port,
                    tls_version=tls_socket.version(),
                    cipher=cipher_info[0] if cipher_info else None,
                    cipher_bits=cipher_info[2] if cipher_info else None,
                    certificate_subject=_format_certificate_name(
                        certificate.get("subject", ())
                    ),
                    certificate_issuer=_format_certificate_name(
                        certificate.get("issuer", ())
                    ),
                    not_before=_format_certificate_date(not_before),
                    not_after=_format_certificate_date(not_after),
                    days_remaining=days_remaining,
                    latency_ms=latency_ms,
                )

    except OSError as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000

        error_code = getattr(exc, "verify_code", None)

        if error_code is None:
            error_code = getattr(exc, "errno", None)

        return TLSResult(
            host=host,
            port=port,
            tls_version=None,
            cipher=None,
            cipher_bits=None,
            certificate_subject=None,
            certificate_issuer=None,
            not_before=None,
            not_after=None,
            days_remaining=None,
            latency_ms=latency_ms,
            error=str(exc),
            error_code=error_code,
        )

