"""Tests for the public demo deploy (PUBLIC_DEMO=1): demo only, fixture intel, proxy-aware rate limits."""

import json
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from api import main
from api.demo import DEMO_FIXTURE_PATH, DEMO_SKIP_REASON, FixtureCache

ROOT = Path(__file__).parent.parent
ALERTS_DIR = ROOT / "alerts"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
# The only indicators the fixture may hold: public test values, never real-world intel.
PUBLIC_TEST_INDICATORS = {EICAR_SHA256}

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def public_demo(monkeypatch):
    monkeypatch.setenv("PUBLIC_DEMO", "1")
    main.triage_limiter.reset()
    main.live_limiter.reset()


def load(filename: str) -> dict:
    return json.loads((ALERTS_DIR / filename).read_text())


def post(data, live: bool = False, headers: dict | None = None) -> httpx.Response:
    return client.post("/api/triage", params={"live": "true"} if live else None, json=data, headers=headers)


# --- Live is never possible --------------------------------------------------------

def test_live_refused_even_with_allow_live(monkeypatch):
    monkeypatch.setenv("ALLOW_LIVE", "1")
    with respx.mock(assert_all_called=False) as mock:
        any_request = mock.route().mock(return_value=httpx.Response(200, json={}))
        response = post({"hostname": "WS-01", "sha256": EICAR_SHA256}, live=True)

    assert response.status_code == 403
    assert response.json() == {"detail": "Live lookups are off on this public demo"}
    assert not any_request.called
    assert main.live_allowed() is False


def test_health_reports_public_demo(monkeypatch):
    monkeypatch.setenv("ALLOW_LIVE", "1")

    body = client.get("/api/health").json()

    assert body["public_demo"] is True
    assert body["live_allowed"] is False


@pytest.mark.parametrize("value", ["", "0", "true", "yes"])
def test_only_exactly_1_turns_it_on(monkeypatch, value):
    monkeypatch.setenv("PUBLIC_DEMO", value)

    assert client.get("/api/health").json()["public_demo"] is False


def test_every_sample_makes_zero_http_calls(monkeypatch):
    monkeypatch.setenv("ALLOW_LIVE", "1")
    with respx.mock(assert_all_called=False) as mock:
        any_request = mock.route().mock(return_value=httpx.Response(200, json={}))
        for path in sorted(ALERTS_DIR.glob("*.json")):
            main.triage_limiter.reset()
            assert post(json.loads(path.read_text())).status_code == 200, path.name

    assert not any_request.called


# --- Fixture intel ----------------------------------------------------------------

def test_eicar_is_served_from_the_fixture():
    body = post(load("eicar.json")).json()

    vt = next(e for e in body["enrichments"] if e["indicator_type"] == "sha256")
    assert vt["cached"] is True
    assert vt["malicious_count"] == 65 and vt["total_engines"] == 75
    assert body["verdict"] == "malicious"


def test_fictional_hashes_stay_not_looked_up():
    body = post(load("s1_threat_sample.json")).json()

    hashes = [e for r in body for e in r["enrichments"] if e["indicator_type"] == "sha256"]
    assert hashes and all(e["skip_reason"] == DEMO_SKIP_REASON for e in hashes)


def test_fixture_holds_only_public_test_indicators():
    results = json.loads(DEMO_FIXTURE_PATH.read_text())["results"]

    assert {r["indicator"] for r in results} <= PUBLIC_TEST_INDICATORS
    assert len(FixtureCache()) == len(results)


def test_fixture_cache_never_touches_disk(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cache = FixtureCache()

    cache.put(cache.get("virustotal", "sha256", EICAR_SHA256))
    assert cache.get("virustotal", "sha256", " " + EICAR_SHA256.upper()).cached is True
    assert cache.get("virustotal", "sha256", "ab" * 32) is None
    assert list(tmp_path.iterdir()) == []


def test_public_demo_does_not_create_the_sqlite_cache(temp_cache_path):
    post(load("eicar.json"))

    assert not temp_cache_path.exists()


def test_real_cache_file_is_git_ignored():
    assert "enrichment_cache.sqlite3*" in (ROOT / ".gitignore").read_text().splitlines()


# --- Client IP behind the proxy ----------------------------------------------------

def ip_for(headers: dict | None = None) -> str:
    """The rate-limit key the app would use for a request with these headers."""
    seen = []
    original = main.triage_limiter.check
    main.triage_limiter.check = lambda key, cost=1: seen.append(key) or original(key, cost)
    try:
        post({"hostname": "WS-01"}, headers=headers)
    finally:
        main.triage_limiter.check = original
    return seen[0]


@pytest.mark.parametrize("header, expected", [
    ("203.0.113.9", "203.0.113.9"),
    ("198.51.100.1, 203.0.113.9", "203.0.113.9"),  # The client's own entry is ignored.
    ("1.1.1.1, 8.8.8.8, 203.0.113.9", "203.0.113.9"),
    ("2001:db8::1", "2001:db8::1"),
    ("203.0.113.9, not-an-ip", "testclient"),  # The proxy's entry must be an IP, else the socket.
    ("203.0.113.9,", "testclient"),
    ("", "testclient"),
])
def test_rightmost_forwarded_for_entry_is_used(header, expected):
    assert ip_for({"X-Forwarded-For": header}) == expected


def test_no_forwarded_for_falls_back_to_the_socket():
    assert ip_for() == "testclient"


def test_spoofed_leftmost_entries_do_not_get_fresh_budgets():
    # An attacker rotating fake leftmost entries still shares the proxy-added address.
    statuses = [
        post({"hostname": "WS-01"}, headers={"X-Forwarded-For": f"10.0.0.{i}, 203.0.113.9"}).status_code
        for i in range(main.triage_limiter.limit + 1)
    ]

    assert statuses[-1] == 429
    assert post({"hostname": "WS-01"}, headers={"X-Forwarded-For": "203.0.113.10"}).status_code == 200


def test_forwarded_for_is_ignored_locally(monkeypatch):
    monkeypatch.delenv("PUBLIC_DEMO")

    assert ip_for({"X-Forwarded-For": "203.0.113.9"}) == "testclient"


# --- Headers and robots.txt ---------------------------------------------------------

def test_hsts_only_on_the_public_demo(monkeypatch):
    assert client.get("/").headers["Strict-Transport-Security"] == main.HSTS_HEADER

    monkeypatch.delenv("PUBLIC_DEMO")
    assert "Strict-Transport-Security" not in client.get("/").headers


def test_existing_security_headers_are_kept():
    response = client.get("/api/health")

    for name, value in main.SECURITY_HEADERS.items():
        assert response.headers[name] == value


def test_robots_txt_allows_the_page_but_not_the_api():
    response = client.get("/robots.txt")

    assert response.status_code == 200
    lines = [line.strip() for line in response.text.splitlines()]
    assert "Disallow: /api/" in lines
    assert "Disallow: /" not in lines


# --- Deploy config ----------------------------------------------------------------

def test_render_yaml_is_demo_only_with_no_secrets():
    import yaml

    service = yaml.safe_load((ROOT / "render.yaml").read_text())["services"][0]
    env = {v["key"]: v for v in service["envVars"]}

    assert service["plan"] == "free"
    assert service["buildCommand"] == "pip install -r requirements.txt"
    assert service["startCommand"] == "uvicorn api.main:app --host 0.0.0.0 --port $PORT"
    assert service["healthCheckPath"] == "/api/health"
    assert env["PUBLIC_DEMO"]["value"] == "1"
    assert not {"VT_API_KEY", "ABUSEIPDB_API_KEY", "ALLOW_LIVE"} & set(env)
    assert all("value" in v and "sync" not in v for v in env.values())  # Nothing to fill in by hand.


def test_bind_is_public_only_on_the_public_demo(monkeypatch):
    from api.__main__ import bind

    monkeypatch.setenv("PORT", "10000")
    assert bind() == ("0.0.0.0", 10000)

    monkeypatch.delenv("PUBLIC_DEMO")
    assert bind() == ("127.0.0.1", 8000)
