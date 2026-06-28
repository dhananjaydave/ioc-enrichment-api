from unittest.mock import patch

from ioc_enrichment.sources.asn_lookup import ASNLookupClient


async def test_not_applicable_for_hash():
    result = await ASNLookupClient().lookup("d" * 64, "hash")
    assert result == {"source": "asn_lookup", "status": "not_applicable"}


async def test_looks_up_ip_directly():
    with patch("ioc_enrichment.sources.asn_lookup._lookup_asn", return_value={
        "ip": "8.8.8.8", "asn": "15169", "asn_description": "GOOGLE", "network_cidr": "8.8.8.0/24", "country": "US",
    }):
        result = await ASNLookupClient().lookup("8.8.8.8", "ip")
    assert result["status"] == "ok"
    assert result["asn"] == "15169"


async def test_resolves_domain_before_lookup():
    with patch("ioc_enrichment.sources.asn_lookup._resolve_to_ip", return_value="93.184.216.34"), \
         patch("ioc_enrichment.sources.asn_lookup._lookup_asn", return_value={"ip": "93.184.216.34", "asn": "1234"}) as mock_lookup:
        result = await ASNLookupClient().lookup("example.com", "domain")
    mock_lookup.assert_called_once_with("93.184.216.34")
    assert result["status"] == "ok"


async def test_domain_that_does_not_resolve_degrades_gracefully():
    with patch("ioc_enrichment.sources.asn_lookup._resolve_to_ip", return_value=None):
        result = await ASNLookupClient().lookup("nonexistent.invalid", "domain")
    assert result["status"] == "error"


async def test_private_ip_returns_no_data():
    result = await ASNLookupClient().lookup("10.0.0.5", "ip")
    assert result["status"] == "error"


async def test_lookup_failure_degrades_gracefully():
    with patch("ioc_enrichment.sources.asn_lookup._lookup_asn", side_effect=RuntimeError("RDAP server unreachable")):
        result = await ASNLookupClient().lookup("8.8.8.8", "ip")
    assert result["status"] == "error"
