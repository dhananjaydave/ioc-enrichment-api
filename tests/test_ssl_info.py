from unittest.mock import patch

from ioc_enrichment.sources.ssl_info import SSLInfoClient, _is_public


def test_is_public_rejects_private_and_special_ranges():
    assert _is_public("127.0.0.1") is False
    assert _is_public("10.0.0.5") is False
    assert _is_public("192.168.1.1") is False
    assert _is_public("169.254.169.254") is False  # cloud metadata endpoint
    assert _is_public("8.8.8.8") is True


async def test_not_applicable_for_non_domain():
    result = await SSLInfoClient().lookup("8.8.8.8", "ip")
    assert result == {"source": "ssl_info", "status": "not_applicable"}


async def test_refuses_to_connect_when_resolved_address_is_not_public():
    """The core SSRF protection: a domain crafted to resolve to a private/
    internal address must never be connected to, regardless of what the
    indicator string itself looks like."""
    with patch("ioc_enrichment.sources.ssl_info._resolve_all", return_value=["127.0.0.1"]), \
         patch("ioc_enrichment.sources.ssl_info.socket.create_connection") as mock_connect:
        result = await SSLInfoClient().lookup("evil-internal-pointer.example", "domain")
    mock_connect.assert_not_called()
    assert result["status"] == "error"


async def test_refuses_when_any_resolved_address_is_not_public():
    """A domain can resolve to multiple addresses (round-robin DNS) - if
    even one of them is non-public, refuse rather than connect to whichever
    one happens to be tried."""
    with patch("ioc_enrichment.sources.ssl_info._resolve_all", return_value=["8.8.8.8", "10.0.0.1"]), \
         patch("ioc_enrichment.sources.ssl_info.socket.create_connection") as mock_connect:
        result = await SSLInfoClient().lookup("mixed.example", "domain")
    mock_connect.assert_not_called()
    assert result["status"] == "error"


async def test_returns_cert_dates_for_public_domain():
    with patch("ioc_enrichment.sources.ssl_info._fetch_cert_dates", return_value={
        "issued_on": "2026-01-01T00:00:00+00:00",
        "expires_on": "2026-12-31T00:00:00+00:00",
        "issuer": "CN=Test CA",
    }):
        result = await SSLInfoClient().lookup("example.com", "domain")
    assert result["status"] == "ok"
    assert result["issued_on"] == "2026-01-01T00:00:00+00:00"


async def test_degrades_gracefully_on_connection_failure():
    with patch("ioc_enrichment.sources.ssl_info._fetch_cert_dates", side_effect=TimeoutError("connect timed out")):
        result = await SSLInfoClient().lookup("unreachable.example", "domain")
    assert result["status"] == "error"
