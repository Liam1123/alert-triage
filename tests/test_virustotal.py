"""Tests for the VirusTotal enricher and triage verdicts.

respx intercepts every httpx request, so these tests never touch the real API.
"""

import httpx
import pytest
import respx

from enrichers.virustotal import API_URL, lookup_sha256
from models import Alert
from triage import triage

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
VT_URL = API_URL.format(sha256=EICAR_SHA256)


@pytest.fixture(autouse=True)
def fake_api_key(monkeypatch):
    """Give every test a fake key so a real one from .env is never used."""
    monkeypatch.setenv("VT_API_KEY", "test-key")


def vt_file_report(malicious: int, undetected: int) -> dict:
    """A trimmed-down VirusTotal /files/{hash} response body."""
    return {
        "data": {
            "id": EICAR_SHA256,
            "type": "file",
            "attributes": {
                "first_submission_date": 1148301722,
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": 0,
                    "undetected": undetected,
                    "harmless": 0,
                },
            },
        }
    }


def alert_with_hash() -> Alert:
    return Alert(hostname="WS-TEST-01", sha256=EICAR_SHA256)


@respx.mock
def test_malicious_hash():
    route = respx.get(VT_URL).mock(
        return_value=httpx.Response(200, json=vt_file_report(malicious=62, undetected=10))
    )

    result = triage(alert_with_hash())

    assert route.called
    assert route.calls.last.request.headers["x-apikey"] == "test-key"
    assert result.verdict == "malicious"
    enrichment = result.enrichments[0]
    assert enrichment.malicious_count == 62
    assert enrichment.total_engines == 72
    assert enrichment.first_seen.year == 2006
    assert enrichment.permalink.endswith(EICAR_SHA256)
    assert enrichment.error is None
    assert "62/72" in result.reasons[0]


@respx.mock
def test_suspicious_hash():
    respx.get(VT_URL).mock(
        return_value=httpx.Response(200, json=vt_file_report(malicious=2, undetected=70))
    )

    result = triage(alert_with_hash())

    assert result.verdict == "suspicious"


@respx.mock
def test_clean_hash():
    respx.get(VT_URL).mock(
        return_value=httpx.Response(200, json=vt_file_report(malicious=0, undetected=72))
    )

    result = triage(alert_with_hash())

    assert result.verdict == "clean"
    assert result.enrichments[0].malicious_count == 0
    assert result.enrichments[0].error is None


@respx.mock
def test_hash_not_found():
    respx.get(VT_URL).mock(
        return_value=httpx.Response(404, json={"error": {"code": "NotFoundError"}})
    )

    result = triage(alert_with_hash())

    assert result.verdict == "unknown"
    assert "not found" in result.enrichments[0].error.lower()
    assert result.enrichments[0].malicious_count is None


@respx.mock
def test_rate_limited():
    respx.get(VT_URL).mock(
        return_value=httpx.Response(429, json={"error": {"code": "QuotaExceededError"}})
    )

    result = triage(alert_with_hash())

    assert result.verdict == "unknown"
    assert "rate limit" in result.enrichments[0].error.lower()


@respx.mock
def test_missing_api_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY")
    route = respx.get(VT_URL)

    result = triage(alert_with_hash())

    assert not route.called  # no request is sent without a key
    assert result.verdict == "unknown"
    assert "VT_API_KEY" in result.enrichments[0].error


@respx.mock
def test_network_error():
    respx.get(VT_URL).mock(side_effect=httpx.ConnectError("connection refused"))

    result = lookup_sha256(EICAR_SHA256)

    assert "network error" in result.error.lower()


def test_alert_without_hash_is_unknown():
    result = triage(Alert(hostname="WS-TEST-01"))

    assert result.verdict == "unknown"
    assert result.enrichments == []
