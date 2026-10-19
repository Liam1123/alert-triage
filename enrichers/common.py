"""Helpers shared by every enricher: building results and making HTTP calls."""

import httpx

from models import EnrichmentResult, IndicatorType

TIMEOUT_SECONDS = 10.0


class LookupFailed(Exception):
    """Raised inside an enricher when an API call fails.

    Enrichers catch this and turn it into an EnrichmentResult with `error`
    set, so it never escapes to the caller.
    """


def error_result(
    source: str, indicator: str, indicator_type: IndicatorType, message: str
) -> EnrichmentResult:
    return EnrichmentResult(
        source=source, indicator=indicator, indicator_type=indicator_type, error=message
    )


def skipped_result(
    source: str, indicator: str, indicator_type: IndicatorType, reason: str
) -> EnrichmentResult:
    return EnrichmentResult(
        source=source, indicator=indicator, indicator_type=indicator_type, skip_reason=reason
    )


def get_json(service: str, url: str, headers: dict, params: dict | None = None) -> dict:
    """GET a URL and return the parsed JSON body.

    `service` is a display name (e.g. "VirusTotal") used in error messages.
    Raises LookupFailed with a readable message for anything other than a
    successful JSON response.
    """
    try:
        response = httpx.get(url, headers=headers, params=params, timeout=TIMEOUT_SECONDS)
    except httpx.TimeoutException:
        raise LookupFailed(f"{service} request timed out")
    except httpx.RequestError as exc:
        raise LookupFailed(f"Network error contacting {service}: {exc}")

    status = response.status_code
    if status == 404:
        raise LookupFailed(f"Indicator not found in {service}")
    if status == 429:
        raise LookupFailed(f"{service} rate limit exceeded (HTTP 429)")
    if status in (401, 403):
        raise LookupFailed(f"{service} rejected the API key (HTTP {status})")
    if status != 200:
        raise LookupFailed(f"Unexpected {service} response (HTTP {status})")

    try:
        return response.json()
    except ValueError:
        raise LookupFailed(f"{service} returned a response that is not valid JSON")
