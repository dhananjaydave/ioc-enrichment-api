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
from .sources.asn_lookup import ASNLookupClient
from .sources.domain_age import DomainAgeClient
from .sources.ssl_info import SSLInfoClient
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
domain_age_client = DomainAgeClient()
ssl_info_client = SSLInfoClient()
asn_lookup_client = ASNLookupClient()

# "reputation" (VirusTotal + AbuseIPDB) feeds the malicious/suspicious/clean
# verdict. The other three are contextual, not scored - a new domain or an
# unusual hosting ASN is evidence to weigh, not a verdict on its own, so
# they're reported separately as "context" rather than mixed into "sources".
ALL_CHECKS = {"reputation", "domain_age", "ssl", "asn"}
DEFAULT_CHECKS = {"reputation"}  # keeps existing callers (e.g. the phishing triage bot) fast and unchanged

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
    context: list[dict] = []


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


def _parse_checks(checks: str | None) -> set[str]:
    if checks is None:
        return set(DEFAULT_CHECKS)  # no param at all - keep existing callers fast and unchanged
    if checks.strip().lower() == "all":
        return set(ALL_CHECKS)
    requested = {c.strip().lower() for c in checks.split(",") if c.strip()}
    unknown = requested - ALL_CHECKS
    if unknown:
        raise ValueError(f"Unknown check(s): {', '.join(sorted(unknown))}. Valid options: {', '.join(sorted(ALL_CHECKS))}")
    return requested or set(DEFAULT_CHECKS)


async def _perform_enrichment(indicator: str, checks: set[str]) -> dict:
    if len(indicator) > MAX_INDICATOR_LENGTH:
        raise ValueError(f"Indicator too long (max {MAX_INDICATOR_LENGTH} characters)")
    indicator_type = detect_type(indicator)

    cache_key = f"{indicator_type}:{indicator}:{','.join(sorted(checks))}"
    cached = cache.get(cache_key)
    if cached:
        return {**cached, "cached": True}

    reputation_results: list[dict] = []
    context_results: list[dict] = []

    tasks = []
    if "reputation" in checks:
        tasks.append(("reputation", vt_client.lookup(indicator, indicator_type)))
        tasks.append(("reputation", abuse_client.lookup(indicator, indicator_type)))
    if "domain_age" in checks:
        tasks.append(("context", domain_age_client.lookup(indicator, indicator_type)))
    if "ssl" in checks:
        tasks.append(("context", ssl_info_client.lookup(indicator, indicator_type)))
    if "asn" in checks:
        tasks.append(("context", asn_lookup_client.lookup(indicator, indicator_type)))

    results = await asyncio.gather(*(t[1] for t in tasks))
    for (bucket, _), result in zip(tasks, results):
        (reputation_results if bucket == "reputation" else context_results).append(result)

    response = {
        "indicator": indicator,
        "type": indicator_type,
        "verdict": compute_verdict(reputation_results),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "cached": False,
        "sources": reputation_results,
        "context": context_results,
    }
    # Don't cache a transient failure (rate limit, network error) as if it
    # were a stable result - that would lock in "unknown" for the full TTL
    # even after the rate limit clears. "skipped"/"not_applicable" are fine
    # to cache since they won't change until someone adds a key.
    if not any(r.get("status") == "error" for r in reputation_results + context_results):
        cache.set(cache_key, response)
    return response


@app.get("/", response_class=HTMLResponse)
def index():
    return (_STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/enrich", response_model=EnrichResponse)
async def enrich(indicator: str, checks: str | None = None, x_api_key: str | None = Header(default=None)):
    """checks: comma-separated subset of reputation,domain_age,ssl,asn (or
    "all"). Defaults to reputation only, so existing integrations stay fast
    and unchanged unless they opt into the extra checks."""
    _check_auth(x_api_key)
    try:
        return await _perform_enrichment(indicator, _parse_checks(checks))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/demo/enrich", response_model=EnrichResponse)
async def demo_enrich(indicator: str, request: Request, checks: str | None = None):
    """Same lookup as /enrich, no API key needed - protected by a tight
    per-IP rate limit instead, so the public landing page can offer a real
    live demo without exposing the real key or the real quota to abuse."""
    if _demo_rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="Demo rate limit reached - try again later, or use your own API key.")
    try:
        return await _perform_enrichment(indicator, _parse_checks(checks))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
