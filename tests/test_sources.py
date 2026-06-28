import respx
from httpx import Response

from ioc_enrichment.sources.abuseipdb import AbuseIPDBClient
from ioc_enrichment.sources.virustotal import VirusTotalClient


async def test_virustotal_skips_without_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    result = await VirusTotalClient().lookup("8.8.8.8", "ip")
    assert result == {"source": "virustotal", "status": "skipped", "reason": "no API key configured"}


async def test_virustotal_ok(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    with respx.mock:
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4").mock(
            return_value=Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 70, "undetected": 5},
                            "reputation": -10,
                        }
                    }
                },
            )
        )
        result = await VirusTotalClient().lookup("1.2.3.4", "ip")

    assert result["status"] == "ok"
    assert result["malicious"] == 2
    assert result["reputation"] == -10


async def test_virustotal_not_found(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    with respx.mock:
        respx.get("https://www.virustotal.com/api/v3/domains/never-seen.example").mock(return_value=Response(404))
        result = await VirusTotalClient().lookup("never-seen.example", "domain")

    assert result == {"source": "virustotal", "status": "not_found"}


async def test_abuseipdb_not_applicable_for_domains():
    result = await AbuseIPDBClient().lookup("example.com", "domain")
    assert result == {"source": "abuseipdb", "status": "not_applicable"}


async def test_abuseipdb_skips_without_api_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    result = await AbuseIPDBClient().lookup("1.2.3.4", "ip")
    assert result == {"source": "abuseipdb", "status": "skipped", "reason": "no API key configured"}


async def test_abuseipdb_ok(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-key")
    with respx.mock:
        respx.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=Response(
                200,
                json={
                    "data": {
                        "abuseConfidenceScore": 87,
                        "totalReports": 42,
                        "countryCode": "US",
                        "isWhitelisted": False,
                    }
                },
            )
        )
        result = await AbuseIPDBClient().lookup("1.2.3.4", "ip")

    assert result["status"] == "ok"
    assert result["abuse_confidence_score"] == 87
    assert result["total_reports"] == 42
