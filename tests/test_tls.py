
"""Tests for TLS diagnostics."""

import socket
import ssl
from unittest.mock import MagicMock

import pytest

from netprobe.tls import TLSResult, check_tls


def test_check_tls_success(monkeypatch):
    raw_socket = MagicMock()
    raw_socket.__enter__.return_value = raw_socket

    tls_socket = MagicMock()
    tls_socket.__enter__.return_value = tls_socket
    tls_socket.version.return_value = "TLSv1.3"
    tls_socket.cipher.return_value = (
        "TLS_AES_256_GCM_SHA384",
        "TLSv1.3",
        256,
    )
    tls_socket.getpeercert.return_value = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "notBefore": "Nov 24 00:00:00 2026 GMT",
        "notAfter": "Feb 22 00:00:00 2027 GMT",
    }

    context = MagicMock()
    context.wrap_socket.return_value = tls_socket

    monkeypatch.setattr(
        "netprobe.tls.socket.create_connection",
        lambda address, timeout: raw_socket,
    )
    monkeypatch.setattr(
        "netprobe.tls.ssl.create_default_context",
        lambda: context,
    )

    result = check_tls("example.com")

    assert isinstance(result, TLSResult)
    assert result.tls_version == "TLSv1.3"
    assert result.cipher == "TLS_AES_256_GCM_SHA384"
    assert result.cipher_bits == 256
    assert "example.com" in result.certificate_subject
    assert "Test CA" in result.certificate_issuer
    assert result.not_before == "2026-11-24T00:00:00+00:00"
    assert result.not_after == "2027-02-22T00:00:00+00:00"
    assert result.error is None


def test_check_tls_connection_error(monkeypatch):
    def raise_connection_error(*args, **kwargs):
        raise OSError("Connection refused")

    monkeypatch.setattr(
        "netprobe.tls.socket.create_connection",
        raise_connection_error,
    )

    result = check_tls("example.com")

    assert result.tls_version is None
    assert result.error == "Connection refused"


def test_check_tls_certificate_error(monkeypatch):
    raw_socket = MagicMock()
    raw_socket.__enter__.return_value = raw_socket

    context = MagicMock()
    context.wrap_socket.side_effect = ssl.SSLCertVerificationError(
        "Certificate verification failed"
    )

    monkeypatch.setattr(
        "netprobe.tls.socket.create_connection",
        lambda *args, **kwargs: raw_socket,
    )
    monkeypatch.setattr(
        "netprobe.tls.ssl.create_default_context",
        lambda: context,
    )

    result = check_tls("example.com")

    assert result.tls_version is None
    assert "Certificate verification failed" in result.error


@pytest.mark.parametrize(
    "host, port, timeout",
    [
        ("", 443, 5.0),
        ("example.com", 0, 5.0),
        ("example.com", 65536, 5.0),
        ("example.com", True, 5.0),
        ("example.com", 443, 0),
        ("example.com", 443, -1),
        ("example.com", 443, float("inf")),
        ("example.com", 443, float("nan")),
    ],
)
def test_check_tls_invalid_parameters(host, port, timeout):
    with pytest.raises(ValueError):
        check_tls(host, port, timeout)

