"""Command-line entry point. This is the only module that prints.

Usage: python cli.py alerts/eicar.json
"""

import json
import sys
from pathlib import Path

from dotenv import load_dotenv
from pydantic import ValidationError

import adapters
from models import Alert, EnrichmentResult, TriageResult
from triage import DECODER_WHERE, triage


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python cli.py <alert.json>", file=sys.stderr)
        return 2

    # Load VT_API_KEY (and anything else) from .env into the environment.
    load_dotenv()

    path = Path(sys.argv[1])
    try:
        # OCSF findings (finding_info + evidences) are converted first.
        alert = Alert.model_validate(adapters.alert_fields(json.loads(path.read_text())))
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1
    except ValidationError as exc:
        print(f"Error: {path} is not a valid alert:\n{exc}", file=sys.stderr)
        return 1
    except ValueError as exc:  # Not JSON at all. (Checked after ValidationError, its subclass.)
        print(f"Error: {path} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    result = triage(alert)
    print_result(result)
    return 0


def print_result(result: TriageResult) -> None:
    print("=" * 60)
    print(f"VERDICT: {result.verdict.upper()}")
    print(f"Tactics: {', '.join(result.tactics) if result.tactics else '(none)'}")
    detection = result.alert.source_detection
    if detection:
        print(f"EDR said: {_describe_detection(detection)}")
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
            print(f"  {field:<15} {value}")

    links = [e.permalink for e in result.enrichments if e.permalink]
    if links:
        print("\nLinks")
        for link in links:
            print(f"  {link}")


def _describe_detection(detection) -> str:
    """'Unsigned script written... (High, Behavioral Engine: ...)' from what the EDR sent."""
    details = ", ".join(part for part in (detection.severity, detection.analytic) if part)
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
