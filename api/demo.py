"""Demo mode: triage without any network calls.

triage() only reaches the network through cache.get_or_lookup(), so demo mode
is a Cache whose misses never call the lookup function. A cached result is
still served. Everything else gets the same local checks the enrichers run
first (invalid hash, private IP, reserved domain), and anything that would
have needed an API call is marked "demo: not looked up".
"""

from collections.abc import Callable

from cache import Cache
from enrichers.common import error_result, skipped_result
from enrichers.indicators import check_domain, check_ip, normalize_domain
from enrichers.virustotal import SHA256_PATTERN
from models import EnrichmentResult, IndicatorType

DEMO_SKIP_REASON = "demo: not looked up"


class DemoCache(Cache):
    def get_or_lookup(
        self,
        source: str,
        indicator_type: IndicatorType,
        indicator: str,
        lookup: Callable[[str], EnrichmentResult],
    ) -> EnrichmentResult:
        """Return the cached result if there is one; never call `lookup`."""
        cached = self.get(source, indicator_type, indicator)
        if cached is not None:
            return cached
        return offline_result(source, indicator_type, indicator)


def offline_result(source: str, indicator_type: IndicatorType, indicator: str) -> EnrichmentResult:
    """What an enricher would say before making its API call, or a demo skip."""
    if indicator_type == "sha256":
        indicator = indicator.strip().lower()
        if not SHA256_PATTERN.match(indicator):
            return error_result(source, indicator, "sha256", "Not a valid SHA256 hash")
    elif indicator_type == "ip":
        indicator = indicator.strip()
        early_result = check_ip(source, indicator)
        if early_result:
            return early_result
    elif indicator_type == "domain":
        indicator = normalize_domain(indicator)
        early_result = check_domain(source, indicator)
        if early_result:
            return early_result

    return skipped_result(source, indicator, indicator_type, DEMO_SKIP_REASON)
