"""Command-line entry point. This is the only module that prints.

Usage: python cli.py alerts/eicar.json
"""

import sys
from pathlib import Path

from dotenv import load_dotenv
from pydantic import ValidationError

from models import Alert, TriageResult
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
    alert = result.alert

    print("=" * 60)
    print(f"VERDICT: {result.verdict.upper()}")
    print("=" * 60)

    print("\nAlert")
    for field, value in alert.model_dump().items():
        if value is not None:
            print(f"  {field:<15} {value}")

    print("\nEnrichments")
    if not result.enrichments:
        print("  (none)")
    for e in result.enrichments:
        print(f"  [{e.source}] {e.indicator_type} {e.indicator}")
        if e.error:
            print(f"    error:       {e.error}")
            continue
        print(f"    detections:  {e.malicious_count}/{e.total_engines}")
        if e.first_seen:
            print(f"    first seen:  {e.first_seen:%Y-%m-%d %H:%M} UTC")
        if e.permalink:
            print(f"    link:        {e.permalink}")

    print("\nReasons")
    for reason in result.reasons:
        print(f"  - {reason}")


if __name__ == "__main__":
    sys.exit(main())
