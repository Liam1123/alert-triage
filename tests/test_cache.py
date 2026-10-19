"""Tests for the SQLite enrichment cache."""

import httpx
import respx

from cache import Cache
from enrichers import virustotal
from models import Alert, EnrichmentResult
from triage import triage

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
VT_URL = virustotal.API_URL.format(sha256=EICAR_SHA256)
VT_BODY = {
    "data": {"attributes": {"last_analysis_stats": {"malicious": 60, "undetected": 10}}}
}


class FakeClock:
    """A clock the test can move forward by hand."""

    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def good_result() -> EnrichmentResult:
    return EnrichmentResult(
        source="virustotal",
        indicator=EICAR_SHA256,
        indicator_type="sha256",
        malicious_count=60,
        total_engines=70,
    )


@respx.mock
def test_second_lookup_comes_from_cache(tmp_path):
    cache = Cache(tmp_path / "c.sqlite3")
    route = respx.get(VT_URL).mock(return_value=httpx.Response(200, json=VT_BODY))
    alert = Alert(hostname="WS-TEST-01", sha256=EICAR_SHA256)

    first = triage(alert, cache=cache)
    second = triage(alert, cache=cache)

    assert route.call_count == 1  # The second triage made no HTTP request.
    assert first.enrichments[0].cached is False
    assert second.enrichments[0].cached is True
    assert second.verdict == first.verdict == "malicious"


def test_cache_expiry(tmp_path):
    clock = FakeClock()
    cache = Cache(tmp_path / "c.sqlite3", ttl_seconds=60, clock=clock)
    cache.put(good_result())

    clock.now += 59
    assert cache.get("virustotal", "sha256", EICAR_SHA256) is not None

    clock.now += 1  # Now exactly 60 seconds old.
    assert cache.get("virustotal", "sha256", EICAR_SHA256) is None


def test_default_ttl_is_24_hours(tmp_path):
    clock = FakeClock()
    cache = Cache(tmp_path / "c.sqlite3", clock=clock)
    cache.put(good_result())

    clock.now += 23 * 60 * 60
    assert cache.get("virustotal", "sha256", EICAR_SHA256) is not None
    clock.now += 60 * 60
    assert cache.get("virustotal", "sha256", EICAR_SHA256) is None


@respx.mock
def test_errors_are_not_cached(tmp_path):
    cache = Cache(tmp_path / "c.sqlite3")
    route = respx.get(VT_URL).mock(
        side_effect=[
            httpx.Response(429),
            httpx.Response(200, json=VT_BODY),
        ]
    )
    alert = Alert(hostname="WS-TEST-01", sha256=EICAR_SHA256)

    first = triage(alert, cache=cache)
    second = triage(alert, cache=cache)

    assert route.call_count == 2  # The 429 was not cached, so we asked again.
    assert first.verdict == "unknown"
    assert second.verdict == "malicious"
    assert second.enrichments[0].cached is False


def test_not_found_and_skips_are_not_cached(tmp_path):
    cache = Cache(tmp_path / "c.sqlite3")
    cache.put(EnrichmentResult(source="virustotal", indicator=EICAR_SHA256,
                               indicator_type="sha256", error="Indicator not found in VirusTotal"))
    cache.put(EnrichmentResult(source="virustotal", indicator="10.0.0.1",
                               indicator_type="ip", skip_reason="non-routable address (private range)"))

    assert cache.get("virustotal", "sha256", EICAR_SHA256) is None
    assert cache.get("virustotal", "ip", "10.0.0.1") is None


def test_cache_key_includes_source_and_type(tmp_path):
    cache = Cache(tmp_path / "c.sqlite3")
    cache.put(good_result())

    assert cache.get("abuseipdb", "sha256", EICAR_SHA256) is None
    assert cache.get("virustotal", "domain", EICAR_SHA256) is None
    assert cache.get("virustotal", "sha256", EICAR_SHA256.upper()) is not None


def test_cache_does_not_store_verdict(tmp_path):
    cache = Cache(tmp_path / "c.sqlite3")
    cache.put(good_result().model_copy(update={"verdict": "malicious"}))

    assert cache.get("virustotal", "sha256", EICAR_SHA256).verdict is None


@respx.mock
def test_triage_default_cache_uses_temp_path(temp_cache_path):
    respx.get(VT_URL).mock(return_value=httpx.Response(200, json=VT_BODY))

    triage(Alert(hostname="WS-TEST-01", sha256=EICAR_SHA256))

    assert temp_cache_path.exists()
