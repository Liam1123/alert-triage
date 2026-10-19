"""VirusTotal file hash enricher (VirusTotal API v3).

Docs: https://docs.virustotal.com/reference/file-info
"""

import os
import re
from datetime import datetime, timezone

import httpx

from models import EnrichmentResult

SOURCE = "virustotal"
API_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
GUI_URL = "https://www.virustotal.com/gui/file/{sha256}"
TIMEOUT_SECONDS = 10.0

SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def lookup_sha256(sha256: str, api_key: str | None = None) -> EnrichmentResult:
    """Look up a SHA256 hash on VirusTotal.

    The API key is read from the VT_API_KEY environment variable unless one
    is passed in. This function never raises: every failure comes back as an
    EnrichmentResult with `error` set.
    """
    sha256 = sha256.strip().lower()

    if api_key is None:
        api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        return _error(sha256, "VT_API_KEY is not set; skipped VirusTotal lookup")

    if not SHA256_PATTERN.match(sha256):
        return _error(sha256, "Not a valid SHA256 hash")

    try:
        response = httpx.get(
            API_URL.format(sha256=sha256),
            headers={"x-apikey": api_key},
            timeout=TIMEOUT_SECONDS,
        )
    except httpx.TimeoutException:
        return _error(sha256, "VirusTotal request timed out")
    except httpx.RequestError as exc:
        return _error(sha256, f"Network error contacting VirusTotal: {exc}")

    if response.status_code == 404:
        return _error(sha256, "Hash not found in VirusTotal")
    if response.status_code == 429:
        return _error(sha256, "VirusTotal rate limit exceeded (HTTP 429)")
    if response.status_code == 401:
        return _error(sha256, "VirusTotal rejected the API key (HTTP 401)")
    if response.status_code != 200:
        return _error(sha256, f"Unexpected VirusTotal response (HTTP {response.status_code})")

    try:
        return _parse_file_report(sha256, response.json())
    except (ValueError, KeyError, TypeError):
        return _error(sha256, "Could not parse VirusTotal response")


def _parse_file_report(sha256: str, body: dict) -> EnrichmentResult:
    """Turn a VirusTotal /files/{hash} JSON body into an EnrichmentResult."""
    attributes = body["data"]["attributes"]

    # last_analysis_stats looks like {"malicious": 60, "undetected": 10, ...}.
    # Adding up every category gives the number of engines that reported.
    stats = attributes["last_analysis_stats"]
    malicious_count = stats.get("malicious", 0)
    total_engines = sum(stats.values())

    first_seen = None
    if "first_submission_date" in attributes:
        # VirusTotal gives Unix timestamps (seconds, UTC).
        first_seen = datetime.fromtimestamp(attributes["first_submission_date"], tz=timezone.utc)

    return EnrichmentResult(
        source=SOURCE,
        indicator=sha256,
        indicator_type="sha256",
        malicious_count=malicious_count,
        total_engines=total_engines,
        first_seen=first_seen,
        permalink=GUI_URL.format(sha256=sha256),
    )


def _error(sha256: str, message: str) -> EnrichmentResult:
    return EnrichmentResult(
        source=SOURCE,
        indicator=sha256,
        indicator_type="sha256",
        error=message,
    )
