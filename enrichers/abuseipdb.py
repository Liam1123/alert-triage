"""AbuseIPDB enricher (API v2): IP address reputation.

Docs: https://docs.abuseipdb.com/#check-endpoint
"""

import os

from enrichers.common import LookupFailed, error_result, get_json
from enrichers.indicators import check_ip
from models import EnrichmentResult

SOURCE = "abuseipdb"
SERVICE = "AbuseIPDB"

API_URL = "https://api.abuseipdb.com/api/v2/check"
GUI_URL = "https://www.abuseipdb.com/check/{ip}"

# Only count reports from the last 90 days.
MAX_AGE_IN_DAYS = 90


def lookup_ip(ip: str, api_key: str | None = None) -> EnrichmentResult:
    """Look up an IP address. Never raises; failures set `error`.

    The API key is read from ABUSEIPDB_API_KEY unless one is passed in.
    Non-routable addresses are skipped without making a call.
    """
    ip = ip.strip()
    early_result = check_ip(SOURCE, ip)
    if early_result:
        return early_result

    if api_key is None:
        api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return error_result(
            SOURCE, ip, "ip", "ABUSEIPDB_API_KEY is not set; skipped AbuseIPDB lookup"
        )

    try:
        body = get_json(
            SERVICE,
            API_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": MAX_AGE_IN_DAYS},
        )
        data = body["data"]
        return EnrichmentResult(
            source=SOURCE,
            indicator=ip,
            indicator_type="ip",
            score=data["abuseConfidenceScore"],
            report_count=data["totalReports"],
            permalink=GUI_URL.format(ip=ip),
        )
    except LookupFailed as exc:
        return error_result(SOURCE, ip, "ip", str(exc))
    except (KeyError, TypeError, ValueError):
        return error_result(SOURCE, ip, "ip", "Could not parse AbuseIPDB response")
