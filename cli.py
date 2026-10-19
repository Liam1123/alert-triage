"""Command-line entry point. This is the only module that prints.

Usage: python cli.py alerts/eicar.json
"""

import sys
from pathlib import Path

from dotenv import load_dotenv
from pydantic import ValidationError

from models import Alert, EnrichmentResult, TriageResult
from triage import triage


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python cli.py <alert.json>", file=sys.stderr)
        return 2

    # Load VT_API_KEY (and anything else) from .env into the environment.
    load_dotenv()

    path = Path(sys.argv[1])
    try:
        alert = Alert.model_validate_json(path.read_text())
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1
    except ValidationError as exc:
        print(f"Error: {path} is not a valid alert:\n{exc}", file=sys.stderr)
        return 1

    result = triage(alert)
    print_result(result)
    return 0


def print_result(result: TriageResult) -> None:
    print("=" * 60)
    print(f"VERDICT: {result.verdict.upper()}")
    print("=" * 60)

    if not result.enrichments:
        print("  (no enrichments)")
    for e in result.enrichments:
        print(f"  {_origin(e):<7} {e.source:<10} {e.indicator_type:<7} {e.indicator}")
        print(f"          -> {_summary(e)}")

    print("\nReasons")
    for reason in result.reasons:
        print(f"  - {reason}")

    print("\nAlert")
    for field, value in result.alert.model_dump().items():
        if value is not None:
            print(f"  {field:<15} {value}")

    links = [e.permalink for e in result.enrichments if e.permalink]
    if links:
        print("\nLinks")
        for link in links:
            print(f"  {link}")


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
