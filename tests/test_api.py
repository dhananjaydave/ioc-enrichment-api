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
