"""Looks up the hosting network/ASN for an IP (or a domain's resolved IP)
via RDAP - no API key needed, queries the regional internet registries
directly. Useful context: infrastructure hosted on a residential/dynamic
ISP ASN or a known bulletproof-hosting provider is a different risk
profile than the same indicator on a major cloud provider's ASN.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket

from ipwhois import IPWhois

logger = logging.getLogger(__name__)

LOOKUP_TIMEOUT_SECONDS = 8


def _resolve_to_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def _lookup_asn(ip_str: str) -> dict | None:
    if not ipaddress.ip_address(ip_str).is_global:
        return None  # nothing meaningful to report for non-public addresses

    try:
        result = IPWhois(ip_str).lookup_rdap(depth=1)
    except Exception:
        return None

    return {
        "ip": ip_str,
        "asn": result.get("asn"),
        "asn_description": result.get("asn_description"),
        "network_cidr": (result.get("network") or {}).get("cidr"),
        "country": result.get("asn_country_code"),
    }


class ASNLookupClient:
    async def lookup(self, indicator: str, indicator_type: str) -> dict:
        if indicator_type not in ("ip", "domain"):
            return {"source": "asn_lookup", "status": "not_applicable"}

        target_ip = indicator if indicator_type == "ip" else None
        if indicator_type == "domain":
            target_ip = await asyncio.to_thread(_resolve_to_ip, indicator)
            if target_ip is None:
                return {"source": "asn_lookup", "status": "error", "reason": "domain did not resolve"}

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(_lookup_asn, target_ip), timeout=LOOKUP_TIMEOUT_SECONDS
            )
        except Exception as exc:
            logger.warning("ASN lookup failed for %s: %s", target_ip, exc)
            return {"source": "asn_lookup", "status": "error", "reason": "RDAP lookup failed or timed out"}

        if result is None:
            return {"source": "asn_lookup", "status": "error", "reason": "no ASN data available for this address"}

        return {"source": "asn_lookup", "status": "ok", **result}
