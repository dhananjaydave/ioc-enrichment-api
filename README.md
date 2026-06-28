# IOC Enrichment API

Takes an indicator of compromise (IP, domain, file hash, or URL) and returns
an aggregated threat-intel verdict by querying multiple free OSINT sources in
parallel — the same first step a SOC analyst does by hand for every alert,
except it takes one request instead of three browser tabs.

```
GET /enrich?indicator=8.8.8.8
```
```json
{
  "indicator": "8.8.8.8",
  "type": "ip",
  "verdict": "clean",
  "checked_at": "2026-06-28T06:42:17Z",
  "cached": false,
  "sources": [
    {"source": "virustotal", "status": "ok", "malicious": 0, "suspicious": 0, "reputation": 42, "link": "..."},
    {"source": "abuseipdb", "status": "ok", "abuse_confidence_score": 0, "total_reports": 0, "link": "..."}
  ]
}
```

## Why this exists

This is the building block behind a typical "phishing email triage" SOAR
workflow: extract IOCs from a reported email → enrich each one → auto-close
if everything's clean, escalate to a human if anything's flagged. This repo
is the enrichment step, built as something you can actually run and test
rather than a vendor-locked Tines/Splunk SOAR config.

## How it works

- **`detector.py`** classifies the raw string (IP via stdlib `ipaddress`,
  hash by hex-length, URL by scheme, domain by regex) so the right API
  endpoint gets called for each source.
- **`sources/`** has one client per OSINT source (VirusTotal, AbuseIPDB).
  Each degrades gracefully: no API key, rate-limited, or a network error all
  produce a `{"status": "skipped"/"error", ...}` result instead of crashing
  the whole lookup - partial enrichment beats no enrichment.
- **`aggregator.py`** is the only place that knows how to compare VirusTotal's
  analysis-stats counts against AbuseIPDB's 0-100 confidence score, and turns
  both into one `clean`/`suspicious`/`malicious`/`unknown` verdict.
- **`cache.py`** is a simple in-memory TTL cache (1 hour by default) so
  repeat lookups of the same indicator don't burn through VirusTotal's free
  tier (~4 requests/minute).
- **`api.py`** is the FastAPI app (`/enrich`, `/health`, auto-generated docs
  at `/docs`). Set `IOC_API_KEY` to require an `X-API-Key` header — if you
  deploy this publicly without it, anyone can burn through *your*
  VirusTotal/AbuseIPDB quota.
- **`cli.py`** is the same lookup without a server: `python -m
  ioc_enrichment.cli 8.8.8.8`.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
copy .env.example .env
```

Both API keys are free and optional - missing ones just get skipped:
- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register

Put them in `.env`, then:

```powershell
# Run the API
uvicorn ioc_enrichment.api:app --reload
# Visit http://localhost:8000/docs for interactive Swagger docs

# Or use the CLI directly
python -m ioc_enrichment.cli 8.8.8.8

# Run the tests (all HTTP calls are mocked - no API keys needed to test)
pytest -v
```

## Deploying for free

`render.yaml` + `Procfile` are set up for [Render.com](https://render.com)'s
free tier (same pattern as render's standard Python web service blueprint).
**Set `IOC_API_KEY`** in the Render dashboard if you do this — without it,
your deployed instance is an open proxy for your own threat-intel quota.

## What's next

- `urlscan.io` as a third source (URL/domain scan history, no API key
  needed for basic search)
- A "submit and rescan" endpoint for files/URLs VirusTotal hasn't seen yet
- This becomes the enrichment step inside an actual phishing-triage bot
  (parse `.eml` → extract IOCs → call this → post a verdict to Slack)
