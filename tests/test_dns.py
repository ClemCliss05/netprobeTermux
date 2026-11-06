
"""Tests for DNS lookup utilities."""

import socket
from unittest.mock import patch

import pytest

from netprobe.dns import DNSLookupResult, lookup_host


def test_lookup_ipv4():
    addresses = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("192.0.2.10", 0),
        )
    ]

    with patch(
        "netprobe.dns.socket.getaddrinfo",
        return_value=addresses,
    ):
        result = lookup_host("example.test")

    assert result.ipv4 == ("192.0.2.10",)
    assert result.ipv6 == ()
    assert result.error is None


def test_lookup_ipv6():
    addresses = [
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("2001:db8::10", 0, 0, 0),
        )
    ]

    with patch(
        "netprobe.dns.socket.getaddrinfo",
        return_value=addresses,
    ):
        result = lookup_host("example.test")

    assert result.ipv4 == ()
    assert result.ipv6 == ("2001:db8::10",)
    assert result.error is None


def test_lookup_multiple_addresses():
    addresses = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("192.0.2.10", 0),
        ),
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("192.0.2.11", 0),
        ),
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("2001:db8::10", 0, 0, 0),
        ),
    ]

    with patch(
        "netprobe.dns.socket.getaddrinfo",
        return_value=addresses,
    ):
        result = lookup_host("example.test")

    assert result.ipv4 == ("192.0.2.10", "192.0.2.11")
    assert result.ipv6 == ("2001:db8::10",)


def test_lookup_duplicate_addresses():
    addresses = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("192.0.2.10", 0),
        ),
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("192.0.2.10", 0),
        ),
    ]

    with patch(
        "netprobe.dns.socket.getaddrinfo",
        return_value=addresses,
    ):
        result = lookup_host("example.test")

    assert result.ipv4 == ("192.0.2.10",)


def test_lookup_dns_error():
    with patch(
        "netprobe.dns.socket.getaddrinfo",
        side_effect=socket.gaierror(8, "Temporary failure"),
    ):
        result = lookup_host("example.test")

    assert result.ipv4 == ()
    assert result.ipv6 == ()
    assert result.error is not None
    assert result.error_code == 8


@pytest.mark.parametrize("host", ["", "   ", None, 123])
def test_lookup_invalid_host(host):
    with pytest.raises(ValueError):
        lookup_host(host)


def test_result_is_immutable():
    result = DNSLookupResult(
        host="example.test",
        ipv4=("192.0.2.10",),
        ipv6=(),
        latency_ms=10.0,
    )

    with pytest.raises(AttributeError):
        result.host = "other.test"

