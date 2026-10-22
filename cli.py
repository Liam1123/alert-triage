"""Command-line entry point. This is the only module that prints.

Usage: python cli.py [--demo] alerts/eicar.json

The file can hold one alert or a list of them (or a SentinelOne API response,
{"data": [...]}); each alert is triaged in turn, then summarised.

--demo uses the web app's demo path (api/demo.py): intel comes from the local
cache only, and nothing is sent to any API. It's the default when neither
VT_API_KEY nor ABUSEIPDB_API_KEY is set, since live lookups couldn't run anyway.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from pydantic import ValidationError

import adapters
from api.demo import DemoCache
from models import Alert, EnrichmentResult, TriageResult
from triage import DECODER_WHERE, triage

# How each input format is named in the output. Mirrors FORMAT_NAMES in web/app.js.
FORMAT_NAMES = {"native": "native", "ocsf": "SentinelOne OCSF", "s1_threat": "SentinelOne threat"}
API_KEY_NAMES = ["VT_API_KEY", "ABUSEIPDB_API_KEY"]  # Same as api/main.py.


def main() -> int:
    parser = argparse.ArgumentParser(prog="python cli.py", description="Triage an EDR alert file.")
    parser.add_argument("path", type=Path, help="alert JSON: one alert, a list, or a SentinelOne API response")
    parser.add_argument("--demo", action="store_true", help="no API calls: intel from the local cache only")
    args = parser.parse_args()

    # Load VT_API_KEY (and anything else) from .env into the environment.
    load_dotenv()

    has_key = any(os.environ.get(name, "").strip() for name in API_KEY_NAMES)
    demo = args.demo or not has_key
    if args.demo:
        print("Mode: demo (local cache only, no API calls)")
    elif demo:
        print("Mode: demo (no API key set, so local cache only, no API calls)")
    else:
        print("Mode: live (indicators not in the cache are looked up)")

    path = args.path
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {path} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    # A list of alerts, or a SentinelOne {"data": [...]} response, is triaged one by one.
    items = adapters.split(data)
    alerts = []
    for index, item in enumerate(items if items is not None else [data]):
        try:
            # OCSF findings and SentinelOne threats are converted first.
            alerts.append((adapters.detect_format(item), Alert.model_validate(adapters.alert_fields(item))))
        except ValidationError as exc:
            which = f"alert {index + 1} in {path}" if items is not None else str(path)
            print(f"Error: {which} is not a valid alert:\n{exc}", file=sys.stderr)
            return 1
    if not alerts:
        print(f"Error: {path} has no alerts in it", file=sys.stderr)
        return 1

    cache = DemoCache() if demo else None  # None → triage() uses the real Cache and live lookups.
    results = [triage(alert, cache).model_copy(update={"input_format": fmt}) for fmt, alert in alerts]
    for number, result in enumerate(results, start=1):
        if len(results) > 1:
            print(f"\nAlert {number} of {len(results)}")
        print_result(result)
    if len(results) > 1:
        print_summary(results)
    return 0


def print_result(result: TriageResult) -> None:
    print("=" * 60)
    print(f"VERDICT: {result.verdict.upper()}")
    print(f"Tactics: {', '.join(result.tactics) if result.tactics else '(none)'}")
    detection = result.alert.source_detection
    if detection:
        print(f"EDR said: {_describe_detection(detection)}")
        if detection.storyline:
            print(f"Storyline: {detection.storyline}")
        for indicator in detection.indicators:
            print(f"  EDR indicator: {indicator}")
    print(f"Detected: {FORMAT_NAMES[result.input_format]}")
    print("=" * 60)

    print("\nEnrichments")
    if not result.enrichments:
        print("  (none)")
    for e in result.enrichments:
        print(f"  {_origin(e):<7} {e.source:<10} {e.indicator_type:<7} {e.indicator}")
        print(f"          -> {_summary(e)}")

    print("\nBehavior")
    if not result.behavior_findings:
        print("  (no rules matched)")
    for f in result.behavior_findings:
        decoded = f" (in {DECODER_WHERE[f.decoder]})" if f.decoder else ""
        print(f"  [{f.severity.upper():<6}] {f.rule_name}{decoded}")
        for t in f.techniques:
            print(f"           {t.id:<10} {t.name}")
        print(f"           evidence: {f.evidence}")

    if result.decoded_command:
        print("\nDecoded command (-EncodedCommand)")
        for line in result.decoded_command.splitlines():
            print(f"  {line}")

    if result.shift_decoded_command:
        print("\nDecoded command (character shift)")
        for line in result.shift_decoded_command.splitlines():
            print(f"  {line}")

    print("\nReasons")
    for reason in result.reasons:
        print(f"  - {reason}")

    print("\nAlert")
    for field, value in result.alert.model_dump(exclude={"source_detection"}).items():
        if value is not None:
            print(f"  {field:<18} {value}")  # Wide enough for original_file_name.

    links = [e.permalink for e in result.enrichments if e.permalink]
    if links:
        print("\nLinks")
        for link in links:
            print(f"  {link}")


def print_summary(results: list[TriageResult]) -> None:
    """One line per alert, in file order: verdict, host, title."""
    print("\n" + "=" * 60)
    print(f"SUMMARY: {len(results)} alerts")
    print("=" * 60)
    for result in results:
        print(f"  {result.verdict.upper():<11} {result.alert.hostname:<20} {alert_title(result)}")


def alert_title(result: TriageResult) -> str:
    """The EDR's title, else the first behavior finding, else a plain note. The web app does the same."""
    detection = result.alert.source_detection
    if detection and detection.title:
        return detection.title
    if result.behavior_findings:
        return result.behavior_findings[0].rule_name
    return "No behavior rule matched"


def _describe_detection(detection) -> str:
    """'Unsigned script written... (High, Behavioral Engine: ...)' from what the EDR sent."""
    confidence = f"{detection.confidence} confidence" if detection.confidence else None
    parts = (detection.severity, detection.classification, confidence, detection.analytic)
    details = ", ".join(part for part in parts if part)
    title = detection.title or "(no title)"
    return f"{title} ({details})" if details else title


def _origin(e: EnrichmentResult) -> str:
    """Where the data came from: the cache, a live API call, or nowhere (skip/error)."""
    if e.cached:
        return "cached"
    if e.succeeded():
        return "live"
    return "-"


def _summary(e: EnrichmentResult) -> str:
    """A short description of one enrichment's outcome."""
    if e.skip_reason:
        return f"skipped: {e.skip_reason}"
    if e.error:
        return f"{e.verdict}: {e.error}"
    if e.score is not None:
        return f"{e.verdict}: abuse score {e.score}/100, {e.report_count} reports"
    return f"{e.verdict}: {e.malicious_count}/{e.total_engines} engines"


if __name__ == "__main__":
    sys.exit(main())
