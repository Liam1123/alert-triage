"""Demo mode: triage without any network calls.

triage() only reaches the network through cache.get_or_lookup(), so demo mode
is a Cache whose misses never call the lookup function. A cached result is
still served. Everything else gets the same local checks the enrichers run
first (invalid hash, private IP, reserved domain), and anything that would
have needed an API call is marked "demo: not looked up".

The public demo (PUBLIC_DEMO=1) has no local cache to serve from, so it uses
FixtureCache: the same rules, but the cached results come from a small
committed file (data/demo_cache.json) held in memory, and nothing is ever
written to disk.
"""

import json
from collections.abc import Callable
from pathlib import Path

from cache import Cache
from enrichers.common import error_result, skipped_result
from enrichers.indicators import check_domain, check_ip, normalize_domain
from enrichers.virustotal import SHA256_PATTERN
from models import EnrichmentResult, IndicatorType

DEMO_SKIP_REASON = "demo: not looked up"
DEMO_FIXTURE_PATH = Path(__file__).parent.parent / "data" / "demo_cache.json"


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


class FixtureCache(DemoCache):
    """A DemoCache whose cached results come from a JSON file, in memory only.

    The fixture is a snapshot, so it never expires. put() does nothing: demo
    mode never makes a lookup, so there is never anything new to store.
    """

    def __init__(self, path: Path = DEMO_FIXTURE_PATH):
        # Cache.__init__ isn't called on purpose: it would create a SQLite file.
        results = [EnrichmentResult.model_validate(r) for r in json.loads(path.read_text())["results"]]
        self._results = {_key(r.source, r.indicator_type, r.indicator): r for r in results}

    def __len__(self) -> int:
        return len(self._results)

    def get(self, source: str, indicator_type: IndicatorType, indicator: str) -> EnrichmentResult | None:
        result = self._results.get(_key(source, indicator_type, indicator))
        return result.model_copy(update={"cached": True}) if result else None

    def put(self, result: EnrichmentResult) -> None:
        pass


def _key(source: str, indicator_type: str, indicator: str) -> tuple[str, str, str]:
    """Same normalisation as the SQLite cache: case, spaces and a trailing dot don't matter."""
    return source, indicator_type, indicator.strip().lower().rstrip(".")


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
