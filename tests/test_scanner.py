"""Tests for TCP port scanning."""

import errno
import socket
from unittest.mock import MagicMock, patch

import pytest

from netprobe.scanner import PortState, scan_port, scan_ports


def test_scan_open_port():
    """An active TCP listener should be detected as open."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen()

        port = server.getsockname()[1]
        results = scan_port("127.0.0.1", port)
        assert len(results) == 1
        result = results[0]

    assert result.state == PortState.OPEN
    assert result.port == port
    assert result.latency_ms >= 0


def test_scan_closed_port():
    """A port without a listener should be detected as closed."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

        results = scan_port("127.0.0.1", port)
        assert len(results) == 1
        result = results[0]

    assert result.state == PortState.CLOSED


def test_invalid_port():
    """Invalid port numbers should raise ValueError."""

    with pytest.raises(ValueError):
        scan_port("127.0.0.1", 70000)


def test_invalid_timeout():
    """A non-positive timeout should raise ValueError."""

    with pytest.raises(ValueError):
        scan_port("127.0.0.1", 80, timeout=0)


def test_scan_multiple_ports():
    """Multiple ports should be scanned in the requested order."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        open_port = server.getsockname()[1]

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temporary:
            temporary.bind(("127.0.0.1", 0))
            closed_port = temporary.getsockname()[1]

        results = scan_ports(
            "127.0.0.1",
            [open_port, closed_port],
        )

    assert len(results) == 2
    assert results[0].port == open_port
    assert results[0].state == PortState.OPEN
    assert results[1].port == closed_port
    assert results[1].state == PortState.CLOSED


def test_scan_port_range():
    """A range of ports should be accepted."""

    results = scan_ports("127.0.0.1", range(8000, 8003))

    assert len(results) == 3
    assert [result.port for result in results] == [8000, 8001, 8002]


def test_scan_empty_port_list():
    """An empty port list should return an empty result."""

    results = scan_ports("127.0.0.1", [])

    assert results == []


def test_scan_multiple_ports_invalid_timeout():
    """Invalid timeout should be rejected even with multiple ports."""

    with pytest.raises(ValueError):
        scan_ports("127.0.0.1", [80, 443], timeout=0)


def test_scan_invalid_port_type():
    """A port must be an integer."""

    with pytest.raises(ValueError):
        scan_port("127.0.0.1", "443")


def test_scan_boolean_port():
    """Boolean values must not be accepted as port numbers."""

    with pytest.raises(ValueError):
        scan_port("127.0.0.1", True)


def test_scan_invalid_host():
    """An empty hostname must be rejected."""

    with pytest.raises(ValueError):
        scan_port("", 80)


def test_scan_invalid_timeout_type():
    """Timeout must be a numeric value."""

    with pytest.raises(ValueError):
        scan_port("127.0.0.1", 80, timeout="invalid")


def test_scan_invalid_port_list():
    """All ports must be validated before scanning starts."""

    with pytest.raises(ValueError):
        scan_ports("127.0.0.1", [80, 443, 70000])


def test_scan_invalid_port_list_type():
    """Ports must be provided as an iterable."""

    with pytest.raises(ValueError):
        scan_ports("127.0.0.1", 80)


def test_scan_generator():
    """Port generators should be supported."""

    ports = (port for port in [8000, 8001, 8002])

    results = scan_ports("127.0.0.1", ports)

    assert [result.port for result in results] == [8000, 8001, 8002]


def test_scan_invalid_host_in_multiple_scan():
    """Host validation should happen before scanning."""

    with pytest.raises(ValueError):
        scan_ports("", [80, 443])



def test_scan_multiple_addresses():
    """Every resolved address should be scanned."""

    addresses = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("192.0.2.10", 443),
        ),
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("192.0.2.11", 443),
        ),
    ]

    first_socket = MagicMock()
    second_socket = MagicMock()

    first_socket.__enter__.return_value = first_socket
    second_socket.__enter__.return_value = second_socket

    first_socket.connect_ex.return_value = errno.ECONNREFUSED
    second_socket.connect_ex.return_value = 0

    with (
        patch(
            "netprobe.scanner.socket.getaddrinfo",
            return_value=addresses,
        ),
        patch(
            "netprobe.scanner.socket.socket",
            side_effect=[first_socket, second_socket],
        ),
    ):
        results = scan_port("example.test", 443)

    assert len(results) == 2
    assert results[0].address == "192.0.2.10"
    assert results[1].address == "192.0.2.11"
    assert results[0].state == PortState.CLOSED
    assert results[1].state == PortState.OPEN


def test_scan_ipv6_address():
    """IPv6 addresses should be supported."""

    addresses = [
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("::1", 443, 0, 0),
        )
    ]

    with (
        patch(
            "netprobe.scanner.socket.getaddrinfo",
            return_value=addresses,
        ),
        patch("netprobe.scanner.socket.socket") as mock_socket,
    ):
        fake_socket = mock_socket.return_value.__enter__.return_value
        fake_socket.connect_ex.return_value = 0

        results = scan_port("localhost", 443)

    assert len(results) == 1
    assert results[0].address == "::1"
    assert results[0].family == socket.AF_INET6
    assert results[0].state == PortState.OPEN


def test_scan_dns_resolution_error():
    """DNS resolution errors should return an error result."""

    dns_error = socket.gaierror(
        socket.EAI_NONAME,
        "Name or service not known",
    )

    with patch(
        "netprobe.scanner.socket.getaddrinfo",
        side_effect=dns_error,
    ):
        results = scan_port("unknown.invalid", 443)

    assert len(results) == 1
    assert results[0].state == PortState.ERROR
    assert results[0].address is None
    assert results[0].family is None
