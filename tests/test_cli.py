
"""Tests for the NetProbe command-line interface."""

import pytest

from netprobe.cli import main, parse_ports
from netprobe.dns import DNSLookupResult
from netprobe.scanner import PortScanResult, PortState

def test_parse_ports():
    assert parse_ports("80,443") == [80, 443]


def test_parse_ports_with_spaces():
    assert parse_ports("22, 80, 443") == [22, 80, 443]


@pytest.mark.parametrize("value", ["abc", "80,abc", "80,,443", ""])
def test_parse_ports_invalid_format(value):
    with pytest.raises(Exception):
        parse_ports(value)


@pytest.mark.parametrize("value", ["0", "65536", "80,70000"])
def test_parse_ports_out_of_range(value):
    with pytest.raises(Exception):
        parse_ports(value)


def test_main_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])

    assert exc.value.code == 0
    assert "Lightweight network diagnostics tool" in capsys.readouterr().out


def test_main_scan(monkeypatch, capsys):
    expected_results = [
        PortScanResult(
            host="example.com",
            port=443,
            state=PortState.OPEN,
            latency_ms=42.5,
            address="93.184.216.34",
        )
    ]

    def fake_scan_ports(host, ports, timeout):
        assert host == "example.com"
        assert ports == [443]
        assert timeout == 3.0
        return expected_results

    monkeypatch.setattr("netprobe.cli.scan_ports", fake_scan_ports)

    exit_code = main(
        ["scan", "example.com", "--ports", "443", "--timeout", "3"]
    )

    output = capsys.readouterr().out

    assert exit_code == 0
    assert "example.com" in output
    assert "93.184.216.34" in output
    assert "OPEN" in output
    assert "42.50 ms" in output


def test_main_default_ports(monkeypatch):
    def fake_scan_ports(host, ports, timeout):
        assert ports == [80, 443]
        return []

    monkeypatch.setattr("netprobe.cli.scan_ports", fake_scan_ports)

    assert main(["scan", "example.com"]) == 0


def test_main_invalid_timeout(monkeypatch):
    with pytest.raises(SystemExit) as exc:
        main(["scan", "example.com", "--timeout", "-1"])

    assert exc.value.code == 2


def test_main_dns_success(monkeypatch, capsys):
    expected_result = DNSLookupResult(
        host="example.com",
        ipv4=("93.184.216.34",),
        ipv6=("2606:2800:220:1:248:1893:25c8:1946",),
        latency_ms=25.5,
    )

    def fake_lookup_host(host):
        assert host == "example.com"
        return expected_result

    monkeypatch.setattr("netprobe.cli.lookup_host", fake_lookup_host)

    exit_code = main(["dns", "example.com"])

    output = capsys.readouterr().out

    assert exit_code == 0
    assert "example.com" in output
    assert "93.184.216.34" in output
    assert "2606:2800:220:1:248:1893:25c8:1946" in output
    assert "25.50 ms" in output


def test_main_dns_error(monkeypatch, capsys):
    expected_result = DNSLookupResult(
        host="invalid-domain.test",
        ipv4=(),
        ipv6=(),
        latency_ms=15.2,
        error="Name or service not known",
        error_code=-2,
    )

    monkeypatch.setattr(
        "netprobe.cli.lookup_host",
        lambda host: expected_result,
    )

    exit_code = main(["dns", "invalid-domain.test"])

    output = capsys.readouterr().out

    assert exit_code == 0
    assert "No IPv4 address found" in output
    assert "No IPv6 address found" in output
    assert "Name or service not known" in output
    assert "Error code: -2" in output
