import pytest
from fastapi.testclient import TestClient

from ioc_enrichment import api

client = TestClient(api.app)


@pytest.fixture(autouse=True)
def _clear_cache():
    api.cache._store.clear()
    yield
    api.cache._store.clear()


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_enrich_rejects_unrecognized_indicator():
    resp = client.get("/enrich", params={"indicator": "not a real indicator !!!"})
    assert resp.status_code == 400


async def _fake_vt_ok(indicator, indicator_type):
    return {"source": "virustotal", "status": "ok", "malicious": 1, "suspicious": 0}


async def _fake_abuse_skipped(indicator, indicator_type):
    return {"source": "abuseipdb", "status": "skipped", "reason": "no API key configured"}


async def _fake_context(source: str):
    return {"source": source, "status": "ok"}


def test_enrich_happy_path(monkeypatch):
    monkeypatch.setattr(api.vt_client, "lookup", _fake_vt_ok)
    monkeypatch.setattr(api.abuse_client, "lookup", _fake_abuse_skipped)

    resp = client.get("/enrich", params={"indicator": "1.2.3.4"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["indicator"] == "1.2.3.4"
    assert body["type"] == "ip"
    assert body["verdict"] == "malicious"
    assert body["cached"] is False


def test_enrich_is_cached_on_second_call(monkeypatch):
    call_count = {"n": 0}

    async def counting_vt(indicator, indicator_type):
        call_count["n"] += 1
        return {"source": "virustotal", "status": "ok", "malicious": 0, "suspicious": 0}

    monkeypatch.setattr(api.vt_client, "lookup", counting_vt)
    monkeypatch.setattr(api.abuse_client, "lookup", _fake_abuse_skipped)

    first = client.get("/enrich", params={"indicator": "5.6.7.8"})
    second = client.get("/enrich", params={"indicator": "5.6.7.8"})

    assert first.json()["cached"] is False
    assert second.json()["cached"] is True
    assert call_count["n"] == 1


def test_transient_source_error_is_not_cached(monkeypatch):
    """A rate-limited/network error shouldn't get locked in for the full
    cache TTL - the next request should retry instead of replaying the
    same stale failure."""
    call_count = {"n": 0}

    async def flaky_vt(indicator, indicator_type):
        call_count["n"] += 1
        return {"source": "virustotal", "status": "error", "reason": "rate limited"}

    monkeypatch.setattr(api.vt_client, "lookup", flaky_vt)
    monkeypatch.setattr(api.abuse_client, "lookup", _fake_abuse_skipped)

    first = client.get("/enrich", params={"indicator": "6.7.8.9"})
    second = client.get("/enrich", params={"indicator": "6.7.8.9"})

    assert first.json()["cached"] is False
    assert second.json()["cached"] is False  # not served from a cached failure
    assert call_count["n"] == 2  # retried, not skipped


def test_enrich_requires_api_key_when_configured(monkeypatch):
    monkeypatch.setattr(api, "API_KEY", "secret123")
    monkeypatch.setattr(api.vt_client, "lookup", _fake_vt_ok)
    monkeypatch.setattr(api.abuse_client, "lookup", _fake_abuse_skipped)

    no_key = client.get("/enrich", params={"indicator": "9.9.9.9"})
    assert no_key.status_code == 401

    wrong_key = client.get("/enrich", params={"indicator": "9.9.9.9"}, headers={"X-API-Key": "wrong"})
    assert wrong_key.status_code == 401

    right_key = client.get("/enrich", params={"indicator": "9.9.9.9"}, headers={"X-API-Key": "secret123"})
    assert right_key.status_code == 200


def test_enrich_rejects_overlong_indicator():
    resp = client.get("/enrich", params={"indicator": "a" * 3000})
    assert resp.status_code == 400


def test_no_checks_param_defaults_to_reputation_only_not_all():
    """Omitting ?checks entirely must behave exactly like before this
    feature existed - reputation only, no real WHOIS/SSL/RDAP calls for
    existing integrations that don't know about the new param."""
    assert api._parse_checks(None) == {"reputation"}


def test_checks_all_keyword_selects_everything():
    assert api._parse_checks("all") == api.ALL_CHECKS


def test_checks_comma_list_selects_only_named_checks():
    assert api._parse_checks("domain_age,ssl") == {"domain_age", "ssl"}


def test_unknown_check_name_is_rejected():
    resp = client.get("/enrich", params={"indicator": "9.9.9.9", "checks": "not_a_real_check"})
    assert resp.status_code == 400


def test_default_checks_only_calls_reputation_sources(monkeypatch):
    """Confirms the fix for a real bug: omitting ?checks must NOT trigger
    the other three (real, unmocked) network-calling sources."""
    called = {"asn": False, "domain_age": False, "ssl": False}

    async def track_asn(indicator, indicator_type):
        called["asn"] = True
        return {"source": "asn_lookup", "status": "ok"}

    async def track_domain_age(indicator, indicator_type):
        called["domain_age"] = True
        return {"source": "domain_age", "status": "ok"}

    async def track_ssl(indicator, indicator_type):
        called["ssl"] = True
        return {"source": "ssl_info", "status": "ok"}

    monkeypatch.setattr(api.vt_client, "lookup", _fake_vt_ok)
    monkeypatch.setattr(api.abuse_client, "lookup", _fake_abuse_skipped)
    monkeypatch.setattr(api.asn_lookup_client, "lookup", track_asn)
    monkeypatch.setattr(api.domain_age_client, "lookup", track_domain_age)
    monkeypatch.setattr(api.ssl_info_client, "lookup", track_ssl)

    resp = client.get("/enrich", params={"indicator": "9.9.9.10"})
    assert resp.status_code == 200
    assert called == {"asn": False, "domain_age": False, "ssl": False}
    assert resp.json()["context"] == []


def test_checks_all_populates_context_alongside_sources(monkeypatch):
    monkeypatch.setattr(api.vt_client, "lookup", _fake_vt_ok)
    monkeypatch.setattr(api.abuse_client, "lookup", _fake_abuse_skipped)
    monkeypatch.setattr(api.asn_lookup_client, "lookup", lambda i, t: _fake_context("asn_lookup"))
    monkeypatch.setattr(api.domain_age_client, "lookup", lambda i, t: _fake_context("domain_age"))
    monkeypatch.setattr(api.ssl_info_client, "lookup", lambda i, t: _fake_context("ssl_info"))

    resp = client.get("/enrich", params={"indicator": "9.9.9.11", "checks": "all"})
    body = resp.json()
    assert resp.status_code == 200
    context_sources = {c["source"] for c in body["context"]}
    assert context_sources == {"asn_lookup", "domain_age", "ssl_info"}
    # context never affects the verdict - only "sources" (reputation) does
    assert body["verdict"] == "malicious"


def test_security_headers_present():
    resp = client.get("/health")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"


def test_index_page_serves_html():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "IOC Enrichment API" in resp.text


@pytest.fixture(autouse=True)
def _clear_demo_rate_limit():
    api._demo_request_log.clear()
    yield
    api._demo_request_log.clear()


def test_demo_enrich_works_without_api_key(monkeypatch):
    monkeypatch.setattr(api, "API_KEY", "secret123")
    monkeypatch.setattr(api.vt_client, "lookup", _fake_vt_ok)
    monkeypatch.setattr(api.abuse_client, "lookup", _fake_abuse_skipped)

    resp = client.get("/demo/enrich", params={"indicator": "1.2.3.4"})
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "malicious"


def test_demo_enrich_rate_limits_per_ip(monkeypatch):
    monkeypatch.setattr(api.vt_client, "lookup", _fake_vt_ok)
    monkeypatch.setattr(api.abuse_client, "lookup", _fake_abuse_skipped)
    monkeypatch.setattr(api, "DEMO_RATE_LIMIT_MAX_REQUESTS", 3)

    headers = {"CF-Connecting-IP": "203.0.113.5"}
    for i in range(3):
        resp = client.get("/demo/enrich", params={"indicator": f"1.2.3.{i}"}, headers=headers)
        assert resp.status_code == 200

    blocked = client.get("/demo/enrich", params={"indicator": "1.2.3.99"}, headers=headers)
    assert blocked.status_code == 429


def test_demo_enrich_rate_limit_uses_cf_connecting_ip_not_spoofable_xff(monkeypatch):
    """A client setting its own X-Forwarded-For shouldn't be able to evade the
    rate limit - only the Cloudflare-set CF-Connecting-IP should count."""
    monkeypatch.setattr(api.vt_client, "lookup", _fake_vt_ok)
    monkeypatch.setattr(api.abuse_client, "lookup", _fake_abuse_skipped)
    monkeypatch.setattr(api, "DEMO_RATE_LIMIT_MAX_REQUESTS", 1)

    real_ip = "203.0.113.7"
    client.get(
        "/demo/enrich",
        params={"indicator": "1.1.1.1"},
        headers={"CF-Connecting-IP": real_ip, "X-Forwarded-For": "1.1.1.1"},
    )
    blocked = client.get(
        "/demo/enrich",
        params={"indicator": "2.2.2.2"},
        # Same real client, spoofing a different X-Forwarded-For each time -
        # should NOT bypass the limit since CF-Connecting-IP is unchanged.
        headers={"CF-Connecting-IP": real_ip, "X-Forwarded-For": "9.9.9.9"},
    )
    assert blocked.status_code == 429
