"""AbuseIPDB v2 API client - IP reputation only (it has no domain/hash/url
endpoint), so non-IP indicators get a "not_applicable" result rather than a
wasted call.
"""

from __future__ import annotations

import os

import httpx

API_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT = 15


class AbuseIPDBClient:
    def __init__(self) -> None:
        self.api_key = os.environ.get("ABUSEIPDB_API_KEY")

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(self, indicator: str, indicator_type: str) -> dict:
        if indicator_type != "ip":
            return {"source": "abuseipdb", "status": "not_applicable"}
        if not self.configured:
            return {"source": "abuseipdb", "status": "skipped", "reason": "no API key configured"}

        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": indicator, "maxAgeInDays": 90}
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                resp = await client.get(API_URL, headers=headers, params=params)
        except httpx.HTTPError as exc:
            return {"source": "abuseipdb", "status": "error", "reason": str(exc)}

        if resp.status_code == 429:
            return {"source": "abuseipdb", "status": "error", "reason": "rate limited"}
        if resp.status_code != 200:
            return {"source": "abuseipdb", "status": "error", "reason": f"HTTP {resp.status_code}"}

        data = resp.json()["data"]
        return {
            "source": "abuseipdb",
            "status": "ok",
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "is_whitelisted": data.get("isWhitelisted"),
            "link": f"https://www.abuseipdb.com/check/{indicator}",
        }
