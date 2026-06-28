"""In-memory TTL cache so repeat lookups of the same indicator don't burn
through free-tier rate limits (VirusTotal's free tier is ~4 requests/minute)."""

from __future__ import annotations

import time


class TTLCache:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl_seconds = ttl_seconds
        self._store: dict[str, tuple[float, dict]] = {}

    def get(self, key: str) -> dict | None:
        entry = self._store.get(key)
        if not entry:
            return None
        timestamp, value = entry
        if time.time() - timestamp > self.ttl_seconds:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: dict) -> None:
        self._store[key] = (time.time(), value)
