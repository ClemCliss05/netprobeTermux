"""Tests for HTTP diagnostic utilities."""

from unittest.mock import MagicMock

import pytest
import urllib.error

from netprobe.http import HTTPResult, check_http


def create_response(
    status=200,
    reason="OK",
    url="https://example.com",
    content_type="text/html",
):
    """Create a simulated HTTP response."""

    response = MagicMock()
    response.status = status
    response.reason = reason
    response.url = url
    response.headers = {"Content-Type": content_type}
    response.__enter__.return_value = response

    return response


def test_check_http_success(monkeypatch):
    response = create_response()

    def fake_urlopen(request, timeout):
        assert request.full_url == "https://example.com"
        assert request.get_method() == "GET"
        assert timeout == 5.0
        return response

    monkeypatch.setattr(
        "netprobe.http.urllib.request.urlopen",
        fake_urlopen,
    )

    result = check_http("https://example.com")

    assert result.status_code == 200
    assert result.reason == "OK"
    assert result.final_url == "https://example.com"
    assert result.content_type == "text/html"
    assert result.error is None
    assert result.latency_ms >= 0


def test_check_http_redirect(monkeypatch):
    response = create_response(
        url="https://www.example.com",
    )

    monkeypatch.setattr(
        "netprobe.http.urllib.request.urlopen",
        lambda request, timeout: response,
    )

    result = check_http("https://example.com")

    assert result.url == "https://example.com"
    assert result.final_url == "https://www.example.com"


def test_check_http_error_status(monkeypatch):
    error = urllib.error.HTTPError(
        "https://example.com/missing",
        404,
        "Not Found",
        {"Content-Type": "text/html"},
        None,
    )

    def fake_urlopen(request, timeout):
        raise error

    monkeypatch.setattr(
        "netprobe.http.urllib.request.urlopen",
        fake_urlopen,
    )

    result = check_http("https://example.com/missing")

    assert result.status_code == 404
    assert result.reason == "Not Found"
    assert result.error is None


def test_check_http_network_error(monkeypatch):
    def fake_urlopen(request, timeout):
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr(
        "netprobe.http.urllib.request.urlopen",
        fake_urlopen,
    )

    result = check_http("https://example.com")

    assert result.status_code is None
    assert result.error == "Connection refused"
    assert result.final_url is None


def test_check_http_invalid_url():
    with pytest.raises(ValueError):
        check_http("ftp://example.com")


@pytest.mark.parametrize("url", ["", "   ", None, 123])
def test_check_http_invalid_host(url):
    with pytest.raises(ValueError):
        check_http(url)


@pytest.mark.parametrize("timeout", [0, -1, True, "5"])
def test_check_http_invalid_timeout(timeout):
    with pytest.raises(ValueError):
        check_http("https://example.com", timeout=timeout)


def test_http_result_is_immutable():
    result = HTTPResult(
        url="https://example.com",
        status_code=200,
        reason="OK",
        final_url="https://example.com",
        latency_ms=10.0,
        content_type="text/html",
    )

    with pytest.raises(AttributeError):
        result.status_code = 404
