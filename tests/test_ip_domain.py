"""Tests for VirusTotal IP/domain lookups, AbuseIPDB, and indicator skipping.

respx intercepts every httpx request, so these tests never touch a real API.
With @respx.mock, any request that has no matching route fails the test, so
"no HTTP call was made" is enforced automatically.
"""

import httpx
import respx

from enrichers import abuseipdb, virustotal
from models import Alert, EnrichmentResult
from triage import triage, verdict_for

# Routable addresses are needed so the lookups aren't skipped. Every response
# below is mocked, so these values say nothing about the real IP or domain.
PUBLIC_IP = "8.8.8.8"
PUBLIC_DOMAIN = "triage-test-domain.com"

VT_IP_URL = virustotal.IP_API_URL.format(ip=PUBLIC_IP)
VT_DOMAIN_URL = virustotal.DOMAIN_API_URL.format(domain=PUBLIC_DOMAIN)


def vt_report(malicious: int, harmless: int) -> dict:
    """A trimmed-down VirusTotal IP or domain response body."""
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": 0,
                    "undetected": 0,
                    "harmless": harmless,
                }
            }
        }
    }


def abuseipdb_report(score: int, reports: int) -> dict:
    """A trimmed-down AbuseIPDB /check response body."""
    return {
        "data": {
            "ipAddress": PUBLIC_IP,
            "isPublic": True,
            "abuseConfidenceScore": score,
            "totalReports": reports,
        }
    }


def mock_abuseipdb(score: int, reports: int) -> respx.Route:
    return respx.get(abuseipdb.API_URL, params={"ipAddress": PUBLIC_IP}).mock(
        return_value=httpx.Response(200, json=abuseipdb_report(score, reports))
    )


# --- VirusTotal IP and domain -------------------------------------------------


@respx.mock
def test_vt_ip_lookup():
    route = respx.get(VT_IP_URL).mock(
        return_value=httpx.Response(200, json=vt_report(malicious=7, harmless=83))
    )

    result = virustotal.lookup_ip(PUBLIC_IP)

    assert route.called
    assert route.calls.last.request.headers["x-apikey"] == "test-vt-key"
    assert result.indicator_type == "ip"
    assert result.malicious_count == 7
    assert result.total_engines == 90
    assert result.permalink == f"https://www.virustotal.com/gui/ip-address/{PUBLIC_IP}"
    assert result.error is None


@respx.mock
def test_vt_domain_lookup():
    respx.get(VT_DOMAIN_URL).mock(
        return_value=httpx.Response(200, json=vt_report(malicious=12, harmless=82))
    )

    result = triage(Alert(hostname="WS-TEST-01", domain=PUBLIC_DOMAIN))

    assert result.verdict == "malicious"
    assert result.enrichments[0].indicator_type == "domain"
    assert result.reasons == [f"domain {PUBLIC_DOMAIN} flagged by 12/94 VT engines (malicious threshold is 5)"]


@respx.mock
def test_vt_domain_is_normalized():
    route = respx.get(VT_DOMAIN_URL).mock(
        return_value=httpx.Response(200, json=vt_report(malicious=0, harmless=90))
    )

    result = virustotal.lookup_domain("  Triage-Test-Domain.COM. ")

    assert route.called
    assert result.indicator == PUBLIC_DOMAIN


# --- AbuseIPDB ---------------------------------------------------------------


@respx.mock
def test_abuseipdb_request_format():
    route = mock_abuseipdb(score=0, reports=0)

    abuseipdb.lookup_ip(PUBLIC_IP)

    request = route.calls.last.request
    assert request.headers["Key"] == "test-abuseipdb-key"
    assert request.url.params["maxAgeInDays"] == "90"


@respx.mock
def test_abuseipdb_high_score_is_malicious():
    mock_abuseipdb(score=92, reports=341)

    result = abuseipdb.lookup_ip(PUBLIC_IP)

    assert result.score == 92
    assert result.report_count == 341
    assert result.malicious_count is None  # Score is kept separate from VT counts.
    assert result.permalink == f"https://www.abuseipdb.com/check/{PUBLIC_IP}"
    assert verdict_for(result)[0] == "malicious"


@respx.mock
def test_abuseipdb_medium_score_is_suspicious():
    mock_abuseipdb(score=40, reports=6)

    assert verdict_for(abuseipdb.lookup_ip(PUBLIC_IP))[0] == "suspicious"


@respx.mock
def test_abuseipdb_low_score_is_clean():
    mock_abuseipdb(score=10, reports=1)

    assert verdict_for(abuseipdb.lookup_ip(PUBLIC_IP))[0] == "clean"


def test_abuseipdb_threshold_boundaries():
    def verdict_at(score: int) -> str:
        result = EnrichmentResult(
            source="abuseipdb", indicator=PUBLIC_IP, indicator_type="ip", score=score, report_count=1
        )
        return verdict_for(result)[0]

    assert verdict_at(75) == "malicious"
    assert verdict_at(74) == "suspicious"
    assert verdict_at(25) == "suspicious"
    assert verdict_at(24) == "clean"


@respx.mock
def test_abuseipdb_missing_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY")

    result = abuseipdb.lookup_ip(PUBLIC_IP)

    assert "ABUSEIPDB_API_KEY" in result.error


# --- Skipping non-routable IPs and reserved domains ---------------------------


@respx.mock
def test_non_routable_ips_are_skipped_without_http():
    cases = {
        "10.1.2.3": "private range",
        "192.168.0.10": "private range",
        "127.0.0.1": "loopback",
        "169.254.10.20": "link-local",
        "203.0.113.5": "documentation range",
        "2001:db8::1": "documentation range",
        "::ffff:10.0.0.1": "private range",
        "240.0.0.1": "reserved range",
    }
    for ip, expected in cases.items():
        for lookup in (virustotal.lookup_ip, abuseipdb.lookup_ip):
            result = lookup(ip)
            assert result.skip_reason == f"non-routable address ({expected})", ip
            assert result.error is None

    assert len(respx.calls) == 0


@respx.mock
def test_skipped_ip_reason_in_triage():
    result = triage(Alert(hostname="WS-TEST-01", remote_ip="203.0.113.5"))

    assert result.verdict == "unknown"
    assert "remote_ip 203.0.113.5 skipped: non-routable address (documentation range)" in result.reasons
    assert len(respx.calls) == 0


@respx.mock
def test_reserved_domains_are_skipped_without_http():
    cases = {
        "c2.example": "reserved TLD (.example)",
        "foo.test": "reserved TLD (.test)",
        "bad.invalid": "reserved TLD (.invalid)",
        "app.localhost": "reserved TLD (.localhost)",
        "www.example.com": "reserved domain (example.com)",
    }
    for domain, expected in cases.items():
        result = virustotal.lookup_domain(domain)
        assert result.skip_reason == expected, domain

    assert len(respx.calls) == 0


@respx.mock
def test_invalid_indicators_are_errors_without_http():
    assert virustotal.lookup_ip("999.1.1.1").error == "Not a valid IP address"
    assert abuseipdb.lookup_ip("not-an-ip").error == "Not a valid IP address"
    assert virustotal.lookup_domain("-bad-.com").error == "Not a valid domain name"
    assert virustotal.lookup_domain("localhost").error == "Not a valid domain name"
    assert len(respx.calls) == 0
