"""Turns per-source results into one verdict. Each source has a different
scoring scheme (VT's analysis stats vs AbuseIPDB's 0-100 confidence score),
so this is the one place that knows how to compare them."""

from __future__ import annotations

ABUSEIPDB_MALICIOUS_THRESHOLD = 75
ABUSEIPDB_SUSPICIOUS_THRESHOLD = 25


def compute_verdict(source_results: list[dict]) -> str:
    """Returns "malicious", "suspicious", "clean", or "unknown" (no source had data)."""
    malicious_signals = 0
    suspicious_signals = 0
    any_data = False

    for result in source_results:
        if result.get("status") != "ok":
            continue
        any_data = True

        if result["source"] == "virustotal":
            if result.get("malicious", 0) > 0:
                malicious_signals += 1
            elif result.get("suspicious", 0) > 0:
                suspicious_signals += 1

        elif result["source"] == "abuseipdb":
            score = result.get("abuse_confidence_score") or 0
            if score >= ABUSEIPDB_MALICIOUS_THRESHOLD:
                malicious_signals += 1
            elif score >= ABUSEIPDB_SUSPICIOUS_THRESHOLD:
                suspicious_signals += 1

    if not any_data:
        return "unknown"
    if malicious_signals > 0:
        return "malicious"
    if suspicious_signals > 0:
        return "suspicious"
    return "clean"
