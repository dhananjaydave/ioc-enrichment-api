"""Fetches the TLS certificate currently presented by a domain - issuance
date is useful alongside domain age (a long-registered domain that just
got a brand-new cert can mean it was recently repurposed for an attack).

This is the one check here that actually opens a connection to whatever
the indicator points at, which makes it the one that needs SSRF
protection: an indicator is fully attacker-controlled input (anyone can
submit any domain to /demo/enrich), and a domain can be made to resolve
to anything via DNS, including the server's own loopback or an internal-
network address. Every resolved IP is checked against private/reserved
ranges before a connection is attempted - if any resolved address isn't
public, the check is refused rather than connecting.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import ssl
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT_SECONDS = 5
HTTPS_PORT = 443


def _resolve_all(hostname: str) -> list[str]:
    infos = socket.getaddrinfo(hostname, HTTPS_PORT, proto=socket.IPPROTO_TCP)
    return list({info[4][0] for info in infos})


def _is_public(ip_str: str) -> bool:
    # is_global is the stdlib's own comprehensive check - it also catches
    # ranges a manual private/loopback/link-local/reserved list would miss,
    # like CGNAT (100.64.0.0/10) and the benchmark-testing range.
    return ipaddress.ip_address(ip_str).is_global


def _fetch_cert_dates(hostname: str) -> dict | None:
    resolved = _resolve_all(hostname)
    if not resolved:
        return None
    if not all(_is_public(ip) for ip in resolved):
        logger.warning("Refusing SSL check for %s - resolves to a non-public address", hostname)
        return None

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # inspecting whatever cert is presented, not making a trust decision

    with socket.create_connection((hostname, HTTPS_PORT), timeout=CONNECT_TIMEOUT_SECONDS) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert_bin = tls_sock.getpeercert(binary_form=True)

    if not cert_bin:
        return None

    # verify_mode=CERT_NONE means getpeercert(binary_form=False) returns
    # nothing useful, so the raw DER bytes are parsed directly instead.
    import cryptography.x509 as x509
    from cryptography.hazmat.backends import default_backend

    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    issuer = cert.issuer.rfc4514_string()

    return {"issued_on": not_before.isoformat(), "expires_on": not_after.isoformat(), "issuer": issuer}


class SSLInfoClient:
    async def lookup(self, indicator: str, indicator_type: str) -> dict:
        if indicator_type != "domain":
            return {"source": "ssl_info", "status": "not_applicable"}

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(_fetch_cert_dates, indicator), timeout=CONNECT_TIMEOUT_SECONDS + 2
            )
        except Exception as exc:
            logger.warning("SSL cert lookup failed for %s: %s", indicator, exc)
            return {"source": "ssl_info", "status": "error", "reason": "could not retrieve certificate"}

        if result is None:
            return {"source": "ssl_info", "status": "error", "reason": "no certificate available or host not publicly reachable"}

        return {"source": "ssl_info", "status": "ok", **result}
