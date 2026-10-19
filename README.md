# Alert Triage Assistant

An alert enrichment and triage assistant for SOC analysts. It takes an EDR-style alert (JSON), enriches its indicators with threat intel APIs, and returns a structured triage result with a verdict and the reasons behind it.

**Milestone 1:** one alert in, a VirusTotal SHA256 lookup, a structured result out.

## Setup

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# then edit .env and set VT_API_KEY=<your VirusTotal API key>
```

`.env` is gitignored. Never commit your key.

## Usage

```bash
python cli.py alerts/eicar.json     # EICAR test file, expected verdict: malicious
python cli.py alerts/unknown.json   # made-up hash, expected verdict: unknown
```

## Verdict rules

| VirusTotal result               | Verdict      |
|---------------------------------|--------------|
| 5 or more engines flag malicious | `malicious`  |
| 1–4 engines flag malicious      | `suspicious` |
| 0 engines flag malicious        | `clean`      |
| Not found, or any lookup error  | `unknown`    |

## Project layout

```
models.py               Pydantic models: Alert, EnrichmentResult, TriageResult
enrichers/virustotal.py VirusTotal v3 file lookup that never raises; errors go in the result
triage.py               triage(alert) -> TriageResult
cli.py                  Command-line entry point (the only module that prints)
alerts/                 Sample alerts (fictional hosts and users)
tests/                  pytest + respx tests (VirusTotal is mocked)
```

## Tests

```bash
python -m pytest -v
```

The tests mock every HTTP call with respx, so they never contact VirusTotal and need no API key.
