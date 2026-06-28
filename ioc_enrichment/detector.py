"""Classifies a raw indicator string as an ip/domain/hash/url before any
enrichment lookup, since each source needs a different endpoint per type."""

from __future__ import annotations

import ipaddress
import re

_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


def detect_type(indicator: str) -> str:
    """Returns "ip", "domain", "hash", or "url". Raises ValueError if none match."""
    value = indicator.strip()

    if value.startswith("http://") or value.startswith("https://"):
        return "url"

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if _HEX_RE.match(value) and len(value) in _HASH_LENGTHS:
        return "hash"

    if _DOMAIN_RE.match(value):
        return "domain"

    raise ValueError(f"Could not determine indicator type for {indicator!r}")


def hash_algorithm(indicator: str) -> str:
    """md5/sha1/sha256, for indicators already confirmed to be hashes."""
    return _HASH_LENGTHS[len(indicator.strip())]
