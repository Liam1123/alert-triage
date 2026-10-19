"""VirusTotal enricher (VirusTotal API v3): file hashes, IP addresses, domains.

Docs: https://docs.virustotal.com/reference/overview
"""

import os
import re
from datetime import datetime, timezone

from enrichers.common import LookupFailed, error_result, get_json
from enrichers.indicators import check_domain, check_ip, normalize_domain
from models import EnrichmentResult, IndicatorType

SOURCE = "virustotal"
SERVICE = "VirusTotal"

API_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
IP_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
DOMAIN_API_URL = "https://www.virustotal.com/api/v3/domains/{domain}"

GUI_URL = "https://www.virustotal.com/gui/file/{sha256}"
IP_GUI_URL = "https://www.virustotal.com/gui/ip-address/{ip}"
DOMAIN_GUI_URL = "https://www.virustotal.com/gui/domain/{domain}"

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def lookup_sha256(sha256: str, api_key: str | None = None) -> EnrichmentResult:
    """Look up a file by SHA256. Never raises; failures set `error`."""
    sha256 = sha256.strip().lower()
    if not SHA256_PATTERN.match(sha256):
        return error_result(SOURCE, sha256, "sha256", "Not a valid SHA256 hash")

    return _lookup(
        indicator=sha256,
        indicator_type="sha256",
        url=API_URL.format(sha256=sha256),
        permalink=GUI_URL.format(sha256=sha256),
        api_key=api_key,
    )


def lookup_ip(ip: str, api_key: str | None = None) -> EnrichmentResult:
    """Look up an IP address. Non-routable addresses are skipped without a call."""
    ip = ip.strip()
    early_result = check_ip(SOURCE, ip)
    if early_result:
        return early_result

    return _lookup(
        indicator=ip,
        indicator_type="ip",
        url=IP_API_URL.format(ip=ip),
        permalink=IP_GUI_URL.format(ip=ip),
        api_key=api_key,
    )


def lookup_domain(domain: str, api_key: str | None = None) -> EnrichmentResult:
    """Look up a domain. Reserved domains (.example, .test, ...) are skipped."""
    domain = normalize_domain(domain)
    early_result = check_domain(SOURCE, domain)
    if early_result:
        return early_result

    return _lookup(
        indicator=domain,
        indicator_type="domain",
        url=DOMAIN_API_URL.format(domain=domain),
        permalink=DOMAIN_GUI_URL.format(domain=domain),
        api_key=api_key,
    )


def _lookup(
    indicator: str,
    indicator_type: IndicatorType,
    url: str,
    permalink: str,
    api_key: str | None,
) -> EnrichmentResult:
    """The part every VirusTotal lookup shares: API key, request, errors, parsing."""
    if api_key is None:
        api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        return error_result(
            SOURCE, indicator, indicator_type, "VT_API_KEY is not set; skipped VirusTotal lookup"
        )

    try:
        body = get_json(SERVICE, url, headers={"x-apikey": api_key})
        return _parse_report(indicator, indicator_type, permalink, body)
    except LookupFailed as exc:
        return error_result(SOURCE, indicator, indicator_type, str(exc))
    except (KeyError, TypeError, ValueError):
        return error_result(SOURCE, indicator, indicator_type, "Could not parse VirusTotal response")


def _parse_report(
    indicator: str, indicator_type: IndicatorType, permalink: str, body: dict
) -> EnrichmentResult:
    """Turn a VirusTotal file/IP/domain JSON body into an EnrichmentResult.

    All three object types share the same `last_analysis_stats` shape.
    """
    attributes = body["data"]["attributes"]

    # last_analysis_stats looks like {"malicious": 60, "undetected": 10, ...}.
    # Adding up every category gives the number of engines that reported.
    stats = attributes["last_analysis_stats"]
    malicious_count = stats.get("malicious", 0)
    total_engines = sum(stats.values())

    first_seen = None
    if "first_submission_date" in attributes:
        # Only files have this. VirusTotal gives Unix timestamps (seconds, UTC).
        first_seen = datetime.fromtimestamp(attributes["first_submission_date"], tz=timezone.utc)

    return EnrichmentResult(
        source=SOURCE,
        indicator=indicator,
        indicator_type=indicator_type,
        malicious_count=malicious_count,
        total_engines=total_engines,
        first_seen=first_seen,
        permalink=permalink,
    )
