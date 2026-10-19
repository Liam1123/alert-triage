"""Tests for combining several enrichment verdicts into one overall verdict."""

import httpx
import respx

from enrichers import abuseipdb, virustotal
from models import Alert, EnrichmentResult
from triage import overall_verdict, triage

CLEAN_SHA256 = "a" * 64
PUBLIC_IP = "8.8.8.8"  # Mocked; chosen only because it is routable.


def finding(verdict: str, skipped: bool = False) -> EnrichmentResult:
    """A minimal enrichment with a verdict already assigned."""
    return EnrichmentResult(
        source="virustotal",
        indicator="x",
        indicator_type="sha256",
        verdict=verdict,
        skip_reason="non-routable address (private range)" if skipped else None,
    )


def test_worst_verdict_wins():
    assert overall_verdict([finding("clean"), finding("malicious")]) == "malicious"
    assert overall_verdict([finding("suspicious"), finding("clean")]) == "suspicious"
    assert overall_verdict([finding("unknown"), finding("suspicious")]) == "suspicious"
    assert overall_verdict([finding("malicious"), finding("suspicious")]) == "malicious"


def test_failed_check_outranks_clean():
    # An error means something went unchecked, so we can't call the alert clean.
    assert overall_verdict([finding("clean"), finding("unknown")]) == "unknown"


def test_skipped_results_are_ignored():
    # A private IP was never going to be in threat intel; it shouldn't drag
    # an otherwise clean alert down to unknown.
    assert overall_verdict([finding("clean"), finding("unknown", skipped=True)]) == "clean"


def test_only_skipped_results_is_unknown():
    skipped = finding("unknown", skipped=True)
    assert overall_verdict([skipped, skipped]) == "unknown"


@respx.mock
def test_clean_hash_plus_malicious_ip_is_malicious():
    respx.get(virustotal.API_URL.format(sha256=CLEAN_SHA256)).mock(
        return_value=httpx.Response(
            200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "undetected": 70}}}}
        )
    )
    respx.get(virustotal.IP_API_URL.format(ip=PUBLIC_IP)).mock(
        return_value=httpx.Response(
            200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "harmless": 89}}}}
        )
    )
    respx.get(abuseipdb.API_URL).mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 100, "totalReports": 512}})
    )
    alert = Alert(
        hostname="WS-TEST-01",
        sha256=CLEAN_SHA256,
        remote_ip=PUBLIC_IP,
        domain="update-check.example",
    )

    result = triage(alert)

    assert result.verdict == "malicious"
    assert [e.verdict for e in result.enrichments] == ["clean", "suspicious", "malicious", "unknown"]
    assert len(result.reasons) == 4  # One reason per enrichment, including the skip.
    assert result.reasons[0] == f"sha256 {CLEAN_SHA256} flagged by 0/70 VT engines"
    assert result.reasons[3] == "domain update-check.example skipped: reserved TLD (.example)"


def test_alert_with_no_indicators():
    result = triage(Alert(hostname="WS-TEST-01"))

    assert result.verdict == "unknown"
    assert result.enrichments == []


def test_duplicate_skip_reasons_are_merged():
    # VirusTotal and AbuseIPDB both skip the same private IP.
    result = triage(Alert(hostname="WS-TEST-01", remote_ip="10.0.0.5"))

    assert len(result.enrichments) == 2
    assert result.reasons == ["remote_ip 10.0.0.5 skipped: non-routable address (private range)"]
