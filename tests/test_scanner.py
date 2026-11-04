"""Tests for TCP port scanning."""

import socket

import pytest

from netprobe.scanner import PortState, scan_port


def test_scan_open_port():
    """An active TCP listener should be detected as open."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen()

        port = server.getsockname()[1]
        result = scan_port("127.0.0.1", port)

    assert result.state == PortState.OPEN
    assert result.port == port
    assert result.latency_ms >= 0


def test_scan_closed_port():
    """A port without a listener should be detected as closed."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

    result = scan_port("127.0.0.1", port)

    assert result.state == PortState.CLOSED


def test_invalid_port():
    """Invalid port numbers should raise ValueError."""

    with pytest.raises(ValueError):
        scan_port("127.0.0.1", 70000)


def test_invalid_timeout():
    """A non-positive timeout should raise ValueError."""

    with pytest.raises(ValueError):
        scan_port("127.0.0.1", 80, timeout=0)
