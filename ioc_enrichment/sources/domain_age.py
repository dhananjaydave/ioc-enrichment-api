"""WHOIS-based domain registration age - a domain registered days ago is a
strong signal on its own, regardless of what reputation sources say (a
brand-new domain has no track record yet, so reputation alone reports
"unknown" rather than "malicious" for genuinely new infrastructure).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import whois

logger = logging.getLogger(__name__)

WHOIS_TIMEOUT_SECONDS = 5


def _lookup_creation_date(domain: str) -> datetime | None:
    try:
        result = whois.whois(domain)
    except Exception:
        return None

    created = result.creation_date
    if isinstance(created, list):
        created = created[0] if created else None
    if created is None:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return created


class DomainAgeClient:
    async def lookup(self, indicator: str, indicator_type: str) -> dict:
        if indicator_type != "domain":
            return {"source": "domain_age", "status": "not_applicable"}

        try:
            created = await asyncio.wait_for(
                asyncio.to_thread(_lookup_creation_date, indicator), timeout=WHOIS_TIMEOUT_SECONDS
            )
        except Exception:
            logger.warning("WHOIS lookup failed or timed out for %s", indicator)
            return {"source": "domain_age", "status": "error", "reason": "WHOIS lookup failed or timed out"}

        if created is None:
            return {"source": "domain_age", "status": "error", "reason": "no WHOIS creation date available"}

        age_days = (datetime.now(timezone.utc) - created).days
        if age_days < 0:
            return {"source": "domain_age", "status": "error", "reason": "WHOIS data returned an implausible date"}

        return {
            "source": "domain_age",
            "status": "ok",
            "registered_on": created.isoformat(),
            "age_days": age_days,
        }
