"""VirusTotal v3 API client. Free tier: ~4 requests/minute, no public IP/domain
relationship data. Every lookup method degrades to a "skipped" result instead
of raising if VIRUSTOTAL_API_KEY isn't set, so the rest of the pipeline still
works with partial enrichment.
"""

from __future__ import annotations

import base64
import os

import httpx

API_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 15


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


class VirusTotalClient:
    def __init__(self) -> None:
        self.api_key = os.environ.get("VIRUSTOTAL_API_KEY")

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(self, indicator: str, indicator_type: str) -> dict:
        if not self.configured:
            return {"source": "virustotal", "status": "skipped", "reason": "no API key configured"}

        endpoint = {
            "ip": f"/ip_addresses/{indicator}",
            "domain": f"/domains/{indicator}",
            "hash": f"/files/{indicator}",
            "url": f"/urls/{_url_id(indicator)}",
        }.get(indicator_type)
        if endpoint is None:
            return {"source": "virustotal", "status": "not_applicable"}

        headers = {"x-apikey": self.api_key}
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                resp = await client.get(f"{API_BASE}{endpoint}", headers=headers)
        except httpx.HTTPError as exc:
            return {"source": "virustotal", "status": "error", "reason": str(exc)}

        if resp.status_code == 404:
            return {"source": "virustotal", "status": "not_found"}
        if resp.status_code == 429:
            return {"source": "virustotal", "status": "error", "reason": "rate limited"}
        if resp.status_code != 200:
            return {"source": "virustotal", "status": "error", "reason": f"HTTP {resp.status_code}"}

        attributes = resp.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})
        return {
            "source": "virustotal",
            "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "link": f"https://www.virustotal.com/gui/search/{indicator}",
        }
