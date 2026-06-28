"""FastAPI app exposing GET /enrich?indicator=<ip|domain|hash|url>.

Run locally:   uvicorn ioc_enrichment.api:app --reload
Docs:          http://localhost:8000/docs (FastAPI auto-generates this)
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
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


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


cache = TTLCache(ttl_seconds=int(os.environ.get("CACHE_TTL_SECONDS", "3600")))
vt_client = VirusTotalClient()
abuse_client = AbuseIPDBClient()

# Optional - if set, every request to /enrich needs a matching X-API-Key header.
# Without this, a publicly deployed instance lets anyone burn through *your*
# VirusTotal/AbuseIPDB quota. /demo/enrich is separately rate-limited instead,
# so the landing page can offer a live demo without needing a key.
API_KEY = os.environ.get("IOC_API_KEY")

DEMO_RATE_LIMIT_WINDOW_SECONDS = 3600
DEMO_RATE_LIMIT_MAX_REQUESTS = 10
_demo_request_log: dict[str, list[float]] = defaultdict(list)

_STATIC_DIR = Path(__file__).resolve().parent / "static"


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


def _client_ip(request: Request) -> str:
    # CF-Connecting-IP is set by Cloudflare's edge itself and can't be spoofed
    # by the client - X-Forwarded-For can (a client can send its own value,
    # and not every proxy in the chain overwrites rather than appends), which
    # would otherwise make the rate limit trivially bypassable by sending a
    # different fake X-Forwarded-For on every request.
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    return request.client.host if request.client else "unknown"


def _demo_rate_limited(ip: str) -> bool:
    now = time.time()
    attempts = _demo_request_log[ip]
    attempts[:] = [t for t in attempts if now - t < DEMO_RATE_LIMIT_WINDOW_SECONDS]
    if len(attempts) >= DEMO_RATE_LIMIT_MAX_REQUESTS:
        return True
    attempts.append(now)
    return False


MAX_INDICATOR_LENGTH = 2048


async def _perform_enrichment(indicator: str) -> dict:
    if len(indicator) > MAX_INDICATOR_LENGTH:
        raise ValueError(f"Indicator too long (max {MAX_INDICATOR_LENGTH} characters)")
    indicator_type = detect_type(indicator)

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
    # Don't cache a transient failure (rate limit, network error) as if it
    # were a stable result - that would lock in "unknown" for the full TTL
    # even after the rate limit clears. "skipped"/"not_applicable" are fine
    # to cache since they won't change until someone adds a key.
    if not any(r.get("status") == "error" for r in results):
        cache.set(cache_key, response)
    return response


@app.get("/", response_class=HTMLResponse)
def index():
    return (_STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/enrich", response_model=EnrichResponse)
async def enrich(indicator: str, x_api_key: str | None = Header(default=None)):
    _check_auth(x_api_key)
    try:
        return await _perform_enrichment(indicator)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/demo/enrich", response_model=EnrichResponse)
async def demo_enrich(indicator: str, request: Request):
    """Same lookup as /enrich, no API key needed - protected by a tight
    per-IP rate limit instead, so the public landing page can offer a real
    live demo without exposing the real key or the real quota to abuse."""
    if _demo_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="Demo rate limit reached - try again later, or use your own API key.")
    try:
        return await _perform_enrichment(indicator)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
