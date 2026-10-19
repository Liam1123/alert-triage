# Alert Triage Assistant

An alert enrichment and triage assistant for SOC analysts. It takes an EDR-style alert (JSON), enriches its indicators with threat intel APIs, and returns a structured triage result with a verdict and the reasons behind it.

**Sources:** VirusTotal (file hashes, IPs, domains) and AbuseIPDB (IPs). Results are cached locally in SQLite for 24 hours.

## Setup

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# then edit .env and set VT_API_KEY and ABUSEIPDB_API_KEY
```

`.env` is gitignored. Never commit your key.

## Usage

```bash
python cli.py alerts/eicar.json     # EICAR test file, expected verdict: malicious
python cli.py alerts/unknown.json   # made-up hash, expected verdict: unknown
python cli.py alerts/multi_indicator.json  # EICAR hash + documentation IP + .example domain
```

`multi_indicator.json` makes one VirusTotal call for the EICAR hash. Its IP and domain are reserved documentation values, so they are skipped and never sent to an API. Expected verdict: malicious.

Each enrichment line shows `live` (fresh API call), `cached` (from the local cache), or `-` (skipped or failed, so no data).

## Verdict rules

Each enrichment gets its own verdict:

| Source     | malicious               | suspicious      | clean        |
|------------|-------------------------|-----------------|--------------|
| VirusTotal | 5+ engines flag it      | 1–4 engines     | 0 engines    |
| AbuseIPDB  | confidence score ≥ 75   | score 25–74     | score < 25   |

Any error (not found, rate limited, missing key, network failure) gives that enrichment `unknown`.

**Overall verdict:** the worst individual verdict, ranked `malicious > suspicious > unknown > clean`. Skipped lookups don't count toward it. A skip means there was nothing to look up, which isn't the same as a failed check. If every lookup was skipped, or the alert has no indicators, the verdict is `unknown`.

**Skipped indicators:** private, loopback, link-local, multicast, reserved, and documentation IP ranges, plus reserved domains (`.example`, `.test`, `.invalid`, `.localhost`, `.local`, `.internal`, and `example.com`/`.net`/`.org`). These are never sent to any API.

## Cache

Successful lookups are stored in `enrichment_cache.sqlite3` in the project folder (gitignored) for 24 hours, keyed by source, indicator type, and indicator. Errors, rate limits, and skips are never cached. Delete the file to force fresh lookups.

## Testing against live data

The sample alerts use only harmless or reserved values. To see real IP and domain results, pick an indicator yourself from a public threat feed, for example:

- [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/browse/) (botnet C2 IPs)
- [abuse.ch ThreatFox](https://threatfox.abuse.ch/browse/) (IPs, domains, hashes)
- [abuse.ch URLhaus](https://urlhaus.abuse.ch/browse/) (malware distribution domains)

Then put it in a local alert file. `alerts/local/` is gitignored, so it won't be committed:

```bash
mkdir -p alerts/local
cat > alerts/local/live_test.json <<'JSON'
{
  "hostname": "WS-LAB-01",
  "remote_ip": "<IP from the feed>",
  "domain": "<domain from the feed>"
}
JSON
python cli.py alerts/local/live_test.json
```

Be careful with live indicators:

- **Don't visit them:** never browse to, ping, or resolve the domains and IPs yourself. This tool only asks the threat intel APIs about them.
- **API quota:** each live run uses your quota (the VirusTotal free tier allows 4 requests per minute). Running the same alert again within 24 hours uses the cache.
- **Old entries:** feed entries go stale. An IP that was malicious last month may come back clean or suspicious now.

## Project layout

```
models.py               Pydantic models: Alert, EnrichmentResult, TriageResult
enrichers/virustotal.py VirusTotal v3: lookup_sha256, lookup_ip, lookup_domain
enrichers/abuseipdb.py  AbuseIPDB v2: lookup_ip
enrichers/common.py     Shared HTTP call + error handling (every enricher uses it)
enrichers/indicators.py IP/domain validation and skip rules
cache.py                SQLite cache with a TTL
triage.py               triage(alert) -> TriageResult; per-source rules + combining
cli.py                  Command-line entry point (the only module that prints)
alerts/                 Sample alerts (fictional hosts and users)
tests/                  pytest + respx tests (all HTTP is mocked)
```

## Tests

```bash
python -m pytest -v
```

The tests mock every HTTP call with respx, so they never contact any real API and need no API keys. They also use a temporary cache file, never the real one.
