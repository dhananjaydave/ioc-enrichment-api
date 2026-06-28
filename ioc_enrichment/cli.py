"""Command-line IOC lookup, no server needed: python -m ioc_enrichment.cli 8.8.8.8"""

from __future__ import annotations

import argparse
import asyncio
import json

from .aggregator import compute_verdict
from .detector import detect_type
from .sources.abuseipdb import AbuseIPDBClient
from .sources.virustotal import VirusTotalClient


async def _lookup(indicator: str) -> dict:
    indicator_type = detect_type(indicator)
    results = await asyncio.gather(
        VirusTotalClient().lookup(indicator, indicator_type),
        AbuseIPDBClient().lookup(indicator, indicator_type),
    )
    return {
        "indicator": indicator,
        "type": indicator_type,
        "verdict": compute_verdict(results),
        "sources": list(results),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Look up an IOC across free threat intel sources.")
    parser.add_argument("indicator", help="IP, domain, hash, or URL to check")
    args = parser.parse_args()

    result = asyncio.run(_lookup(args.indicator))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
