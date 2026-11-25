
"""Tests for the NetProbe command-line interface."""

import pytest

from netprobe.cli import main, parse_ports
from netprobe.dns import DNSLookupResult
from netprobe.http import HTTPResult
from netprobe.scanner import PortScanResult, PortState
from netprobe.tls import TLSResult

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


def test_main_http_success(monkeypatch, capsys):
    expected_result = HTTPResult(
        url="https://example.com",
        status_code=200,
        reason="OK",
        final_url="https://example.com",
        latency_ms=125.5,
        content_type="text/html",
    )

    def fake_check_http(url, timeout):
        assert url == "https://example.com"
        assert timeout == 5.0
        return expected_result

    monkeypatch.setattr("netprobe.cli.check_http", fake_check_http)

    assert main(["http", "https://example.com"]) == 0

    output = capsys.readouterr().out
    assert "200 OK" in output
    assert "125.50 ms" in output
    assert "text/html" in output


def test_main_http_error_status(monkeypatch, capsys):
    expected_result = HTTPResult(
        url="https://example.com/missing",
        status_code=404,
        reason="Not Found",
        final_url="https://example.com/missing",
        latency_ms=80.0,
        content_type="text/html",
    )

    monkeypatch.setattr(
        "netprobe.cli.check_http",
        lambda url, timeout: expected_result,
    )

    assert main(["http", "https://example.com/missing"]) == 0

    output = capsys.readouterr().out
    assert "404 Not Found" in output


def test_main_http_network_error(monkeypatch, capsys):
    expected_result = HTTPResult(
        url="https://example.com",
        status_code=None,
        reason=None,
        final_url=None,
        latency_ms=5000.0,
        content_type=None,
        error="Connection timed out",
    )

    monkeypatch.setattr(
        "netprobe.cli.check_http",
        lambda url, timeout: expected_result,
    )

    assert main(["http", "https://example.com"]) == 0

    output = capsys.readouterr().out
    assert "NO RESPONSE" in output
    assert "Connection timed out" in output


def test_main_tls_success(monkeypatch, capsys):
    expected = TLSResult(
        host="example.com",
        port=443,
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        certificate_subject="commonName=example.com",
        certificate_issuer="commonName=Test CA",
        not_before="2026-11-24T00:00:00+00:00",
        not_after="2027-02-22T00:00:00+00:00",
        days_remaining=89,
        latency_ms=120.5,
    )

    monkeypatch.setattr(
        "netprobe.cli.check_tls",
        lambda host, port, timeout: expected,
    )

    assert main(["tls", "example.com"]) == 0

    output = capsys.readouterr().out
    assert "Status: VERIFIED" in output
    assert "TLSv1.3" in output
    assert "89" in output


def test_main_tls_failure(monkeypatch, capsys):
    expected = TLSResult(
        host="example.com",
        port=443,
        tls_version=None,
        cipher=None,
        cipher_bits=None,
        certificate_subject=None,
        certificate_issuer=None,
        not_before=None,
        not_after=None,
        days_remaining=None,
        latency_ms=100.0,
        error="Certificate verification failed",
        error_code=1,
    )

    monkeypatch.setattr(
        "netprobe.cli.check_tls",
        lambda host, port, timeout: expected,
    )

    assert main(["tls", "example.com"]) == 0

    output = capsys.readouterr().out
    assert "Status: FAILED" in output
    assert "Certificate verification failed" in output


def test_main_tls_custom_port(monkeypatch, capsys):
    expected = TLSResult(
        host="example.com",
        port=8443,
        tls_version=None,
        cipher=None,
        cipher_bits=None,
        certificate_subject=None,
        certificate_issuer=None,
        not_before=None,
        not_after=None,
        days_remaining=None,
        latency_ms=100.0,
        error="Connection refused",
    )

    def fake_check_tls(host, port, timeout):
        assert host == "example.com"
        assert port == 8443
        assert timeout == 3.0
        return expected

    monkeypatch.setattr("netprobe.cli.check_tls", fake_check_tls)

    assert main([
        "tls", "example.com", "--port", "8443", "--timeout", "3"
    ]) == 0

    output = capsys.readouterr().out
    assert "example.com:8443" in output
    assert "Connection refused" in output

