"""FastAPI app exposing GET /enrich?indicator=<ip|domain|hash|url>.

Run locally:   uvicorn ioc_enrichment.api:app --reload
Docs:          http://localhost:8000/docs (FastAPI auto-generates this)
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from .aggregator import compute_verdict
from .cache import TTLCache
from .detector import detect_type
from .sources.abuseipdb import AbuseIPDBClient
from .sources.virustotal import VirusTotalClient

app = FastAPI(
    title="IOC Enrichment API",
    description="Aggregates threat intel for IPs, domains, hashes, and URLs from free OSINT sources.",
    version="1.0.0",
)

cache = TTLCache(ttl_seconds=int(os.environ.get("CACHE_TTL_SECONDS", "3600")))
vt_client = VirusTotalClient()
abuse_client = AbuseIPDBClient()

# Optional - if set, every request needs a matching X-API-Key header. Without
# this, a publicly deployed instance lets anyone burn through *your*
# VirusTotal/AbuseIPDB quota.
API_KEY = os.environ.get("IOC_API_KEY")


class EnrichResponse(BaseModel):
    indicator: str
    type: str
    verdict: str
    checked_at: str
    cached: bool
    sources: list[dict]


def _check_auth(x_api_key: str | None) -> None:
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/enrich", response_model=EnrichResponse)
async def enrich(indicator: str, x_api_key: str | None = Header(default=None)):
    _check_auth(x_api_key)

    try:
        indicator_type = detect_type(indicator)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    cache_key = f"{indicator_type}:{indicator}"
    cached = cache.get(cache_key)
    if cached:
        return {**cached, "cached": True}

    results = await asyncio.gather(
        vt_client.lookup(indicator, indicator_type),
        abuse_client.lookup(indicator, indicator_type),
    )
    response = {
        "indicator": indicator,
        "type": indicator_type,
        "verdict": compute_verdict(results),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "cached": False,
        "sources": list(results),
    }
    cache.set(cache_key, response)
    return response
