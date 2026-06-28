from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from ioc_enrichment.sources.domain_age import DomainAgeClient


def _ago(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


async def test_not_applicable_for_non_domain():
    result = await DomainAgeClient().lookup("8.8.8.8", "ip")
    assert result == {"source": "domain_age", "status": "not_applicable"}


async def test_returns_age_for_domain():
    with patch("ioc_enrichment.sources.domain_age._lookup_creation_date", return_value=_ago(10)):
        result = await DomainAgeClient().lookup("example.com", "domain")
    assert result["status"] == "ok"
    assert result["age_days"] == 10


async def test_degrades_gracefully_when_whois_unavailable():
    with patch("ioc_enrichment.sources.domain_age._lookup_creation_date", return_value=None):
        result = await DomainAgeClient().lookup("example.com", "domain")
    assert result["status"] == "error"


async def test_degrades_gracefully_on_exception():
    with patch("ioc_enrichment.sources.domain_age._lookup_creation_date", side_effect=RuntimeError("boom")):
        result = await DomainAgeClient().lookup("example.com", "domain")
    assert result["status"] == "error"
