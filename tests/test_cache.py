import time

from ioc_enrichment.cache import TTLCache


def test_get_returns_none_when_missing():
    cache = TTLCache(ttl_seconds=60)
    assert cache.get("nope") is None


def test_set_then_get_round_trips():
    cache = TTLCache(ttl_seconds=60)
    cache.set("key", {"a": 1})
    assert cache.get("key") == {"a": 1}


def test_expired_entry_returns_none():
    cache = TTLCache(ttl_seconds=0)
    cache.set("key", {"a": 1})
    time.sleep(0.01)
    assert cache.get("key") is None
