"""Tests for the FastAPI backend (api/main.py).

The TestClient talks to the app in-process, so respx only sees the calls the
enrichers would make to VirusTotal and AbuseIPDB, never the test's own requests.
The client isn't used as a context manager, so the startup hook (load_dotenv)
never runs and .env is never read.
"""

import json
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

import adapters
from api import main
from api.demo import DEMO_SKIP_REASON
from api.ratelimit import RateLimiter
from cache import Cache
from models import EnrichmentResult

ALERTS_DIR = Path(__file__).parent.parent / "alerts"
WEB_DIR = Path(__file__).parent.parent / "web"
SAMPLES = sorted(p.name for p in ALERTS_DIR.glob("*.json"))
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def fresh_rate_limits():
    main.triage_limiter.reset()
    main.live_limiter.reset()


@pytest.fixture(autouse=True)
def live_not_allowed(monkeypatch):
    monkeypatch.delenv("ALLOW_LIVE", raising=False)


def load(filename: str) -> dict:
    return json.loads((ALERTS_DIR / filename).read_text())


def post_triage(alert: dict, live: bool = False) -> httpx.Response:
    return client.post("/api/triage", params={"live": "true"} if live else None, json=alert)


def vt_file_report(malicious: int, undetected: int) -> dict:
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "undetected": undetected}}}}


# --- Triage in demo mode ------------------------------------------------------

@pytest.mark.parametrize("filename", SAMPLES)
def test_triage_each_sample(filename):
    response = post_triage(load(filename))

    assert response.status_code == 200
    sample = load(filename)
    items = adapters.split(sample)
    # A file of several alerts comes back as a list, one result per alert.
    bodies = response.json() if items is not None else [response.json()]
    for body, item in zip(bodies, items if items is not None else [sample], strict=True):
        assert body["verdict"] in {"malicious", "suspicious", "clean", "unknown"}
        assert body["reasons"]
        assert body["input_format"] == adapters.detect_format(item)
        if adapters.detect_format(item) == "native":
            assert body["alert"] == {**dict.fromkeys(body["alert"]), **item}
        else:
            assert body["alert"]["hostname"] == adapters.alert_fields(item)["hostname"]


@pytest.mark.parametrize("filename, expected", [
    ("encoded_powershell.json", "malicious"),
    ("certutil_download.json", "malicious"),
    ("shadow_delete.json", "malicious"),
    ("office_macro.json", "malicious"),
    ("multi_indicator.json", "malicious"),  # The Outlook → cmd behavior rule alone is high.
    ("benign_admin.json", "clean"),
    ("xss_probe.json", "malicious"),
])
def test_demo_verdicts_for_offline_samples(filename, expected):
    assert post_triage(load(filename)).json()["verdict"] == expected


def test_demo_mode_makes_zero_http_calls():
    with respx.mock(assert_all_called=False) as mock:
        any_request = mock.route().mock(return_value=httpx.Response(200, json={}))
        for filename in SAMPLES:
            main.triage_limiter.reset()  # This test is about HTTP calls, not the rate limit.
            assert post_triage(load(filename)).status_code == 200

    assert not any_request.called
    assert len(mock.calls) == 0


def test_demo_marks_lookups_it_would_have_made():
    body = post_triage(load("eicar.json")).json()

    hash_result = next(e for e in body["enrichments"] if e["indicator_type"] == "sha256")
    assert hash_result["skip_reason"] == DEMO_SKIP_REASON
    assert hash_result["cached"] is False
    # The documentation-range IP is skipped for its own reason, as in live mode.
    ip_results = [e for e in body["enrichments"] if e["indicator_type"] == "ip"]
    assert all("documentation range" in e["skip_reason"] for e in ip_results)


def test_demo_still_reports_invalid_indicators():
    body = post_triage({"hostname": "WS-01", "sha256": "not-a-hash"}).json()

    assert body["enrichments"][0]["error"] == "Not a valid SHA256 hash"
    assert body["verdict"] == "unknown"


@respx.mock
def test_demo_serves_cached_results():
    Cache().put(EnrichmentResult(
        source="virustotal", indicator=EICAR_SHA256, indicator_type="sha256",
        malicious_count=60, total_engines=70,
    ))

    body = post_triage(load("eicar.json")).json()

    hash_result = next(e for e in body["enrichments"] if e["indicator_type"] == "sha256")
    assert hash_result["cached"] is True
    assert hash_result["verdict"] == "malicious"
    assert body["verdict"] == "malicious"
    assert len(respx.calls) == 0


def test_evidence_highlights_are_returned():
    body = post_triage(load("encoded_powershell.json")).json()

    cradle = next(f for f in body["behavior_findings"] if f["rule_id"] == "powershell_download_cradle")
    start, end = cradle["highlights"][0]
    assert cradle["evidence"][start:end].lower() in {"iex", "net.webclient", "downloadstring"}


# --- Live mode ----------------------------------------------------------------

def test_live_refused_without_allow_live():
    with respx.mock(assert_all_called=False) as mock:
        any_request = mock.route().mock(return_value=httpx.Response(200, json={}))
        response = post_triage(load("eicar.json"), live=True)

    assert response.status_code == 403
    assert response.json() == {"detail": "Live lookups are disabled on this server"}
    assert not any_request.called


@respx.mock
def test_live_allowed_with_allow_live(monkeypatch):
    monkeypatch.setenv("ALLOW_LIVE", "1")
    route = respx.get(f"https://www.virustotal.com/api/v3/files/{EICAR_SHA256}").mock(
        return_value=httpx.Response(200, json=vt_file_report(malicious=60, undetected=10))
    )

    response = post_triage({"hostname": "WS-01", "sha256": EICAR_SHA256}, live=True)

    assert response.status_code == 200
    assert route.called
    assert response.json()["enrichments"][0]["cached"] is False
    assert response.json()["verdict"] == "malicious"


# --- Input validation ---------------------------------------------------------

def test_oversized_body_rejected():
    alert = {"hostname": "WS-01", "command_line": "A" * (65 * 1024)}

    response = post_triage(alert)

    assert response.status_code == 413
    assert "64 KB" in response.json()["detail"]


def test_oversized_body_without_content_length_rejected():
    def chunks():
        yield b'{"hostname": "WS-01", "command_line": "'
        for _ in range(70):
            yield b"A" * 1024
        yield b'"}'

    response = client.post("/api/triage", content=chunks(), headers={"Content-Type": "application/json"})

    assert response.status_code == 413


def test_unknown_field_rejected():
    response = post_triage({"hostname": "WS-01", "process_id": 4242})

    assert response.status_code == 422
    assert response.json()["errors"] == [{"field": "process_id", "message": "Extra inputs are not permitted"}]


def test_long_string_field_rejected():
    response = post_triage({"hostname": "H" * 300})

    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "hostname"


def test_validation_errors_do_not_echo_input():
    payload = "<script>alert(1)</script>" * 20
    response = post_triage({"hostname": payload})

    assert response.status_code == 422
    assert "<script>" not in response.text


def test_missing_hostname_rejected():
    response = post_triage({"user": "LAB\\someone"})

    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "hostname"


def test_invalid_json_rejected():
    response = client.post("/api/triage", content=b'{"hostname": ', headers={"Content-Type": "application/json"})

    assert response.status_code == 400
    assert response.json() == {"detail": "Request body is not valid JSON"}


def test_non_json_content_type_rejected():
    response = client.post("/api/triage", content=b'{"hostname": "WS-01"}', headers={"Content-Type": "text/plain"})

    assert response.status_code == 415


# --- Rate limiting ------------------------------------------------------------

def test_rate_limit_triggers():
    for _ in range(main.triage_limiter.limit):
        assert post_triage({"hostname": "WS-01"}).status_code == 200

    response = post_triage({"hostname": "WS-01"})

    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1
    assert response.json()["detail"] == "Rate limit reached"


def test_live_rate_limit_is_stricter(monkeypatch):
    monkeypatch.setenv("ALLOW_LIVE", "1")
    alert = {"hostname": "WS-01"}  # No indicators, so live mode has nothing to call.

    statuses = [post_triage(alert, live=True).status_code for _ in range(main.live_limiter.limit + 1)]

    assert statuses == [200] * main.live_limiter.limit + [429]
    assert post_triage(alert).status_code == 200  # Demo triage still has budget left.


def test_rate_limiter_window_slides():
    now = [0.0]
    limiter = RateLimiter(limit=2, window_seconds=60, clock=lambda: now[0])

    assert limiter.check("a") is None
    assert limiter.check("a") is None
    assert limiter.check("a") == 60
    assert limiter.check("b") is None  # Separate clients, separate budgets.

    now[0] = 59.5
    assert limiter.check("a") == 1
    now[0] = 60.0
    assert limiter.check("a") is None


# --- Keys, health, headers ----------------------------------------------------

def test_health_reports_keys_as_booleans_only():
    response = client.get("/api/health")

    body = response.json()
    assert body == {
        "status": "ok",
        "keys": {"VT_API_KEY": True, "ABUSEIPDB_API_KEY": True},
        "live_allowed": False,
    }
    assert "test-vt-key" not in response.text
    assert "test-abuseipdb-key" not in response.text


def test_health_reports_missing_keys(monkeypatch):
    monkeypatch.delenv("VT_API_KEY")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "   ")

    assert client.get("/api/health").json()["keys"] == {"VT_API_KEY": False, "ABUSEIPDB_API_KEY": False}


@respx.mock
def test_keys_never_appear_in_responses(monkeypatch):
    monkeypatch.setenv("ALLOW_LIVE", "1")
    respx.get(url__startswith="https://www.virustotal.com/").mock(return_value=httpx.Response(401))
    respx.get(url__startswith="https://api.abuseipdb.com/").mock(return_value=httpx.Response(500))
    alert = {"hostname": "WS-01", "sha256": EICAR_SHA256, "remote_ip": "8.8.8.8", "domain": "ok.example"}

    responses = [
        post_triage(alert, live=True),
        post_triage(alert),
        client.get("/api/health"),
        client.get("/api/samples"),
    ]

    for response in responses:
        assert "test-vt-key" not in response.text
        assert "test-abuseipdb-key" not in response.text


@pytest.mark.parametrize("method, path, kwargs", [
    ("get", "/", {}),
    ("get", "/app.js", {}),
    ("get", "/api/health", {}),
    ("get", "/api/samples", {}),
    ("get", "/no-such-page", {}),
    ("post", "/api/triage", {"json": {"hostname": "WS-01"}}),
    ("post", "/api/triage", {"json": {"bogus": 1}}),
    ("post", "/api/triage", {"content": b"x" * 70_000, "headers": {"Content-Type": "application/json"}}),
])
def test_security_headers_on_every_response(method, path, kwargs):
    response = getattr(client, method)(path, **kwargs)

    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_no_permissive_cors():
    response = client.options(
        "/api/triage",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )

    assert "access-control-allow-origin" not in response.headers


def test_unexpected_error_is_generic(monkeypatch):
    def broken_triage(alert, cache=None):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(main, "triage", broken_triage)

    response = post_triage({"hostname": "WS-01"})

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "secret internal detail" not in response.text


# --- Samples and the static app -----------------------------------------------

def test_samples_lists_every_alert_file():
    body = client.get("/api/samples").json()

    assert [s["name"] for s in body] == [Path(name).stem for name in SAMPLES]
    assert body[0]["alert"] == load(SAMPLES[0])


def test_index_is_served():
    response = client.get("/")

    assert response.status_code == 200
    assert "<title>Alert Triage</title>" in response.text


def test_frontend_never_uses_html_sinks():
    source = (WEB_DIR / "app.js").read_text()
    code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("//"))

    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in code, sink


def test_html_has_no_inline_scripts_or_third_party_assets():
    html = (WEB_DIR / "index.html").read_text()

    assert "<script>" not in html
    assert "http://" not in html
    for line in html.splitlines():
        if "https://" in line:
            assert "github.com" in line  # The repo link is the only external URL.


# --- OCSF input ---------------------------------------------------------------

def test_ocsf_alert_is_converted_and_triaged():
    body = post_triage(load("ocsf_clipboard_stager.json")).json()

    assert body["verdict"] == "malicious"
    assert body["alert"]["hostname"] == "WS-FIN-0112"
    assert body["alert"]["source_detection"] == {
        "title": "Unsigned PowerShell script written to Themes folder",
        "severity": "High",
        "analytic": "Behavioral Engine: Obfuscated Script Loader",
    }
    assert "[Windows.Forms.Clipboard]::GetText()" in body["shift_decoded_command"]
    assert any(f["decoder"] == "char_shift" for f in body["behavior_findings"])


def test_ocsf_strict_caps_apply_after_conversion():
    data = load("ocsf_clipboard_stager.json")
    data["evidences"][0]["process"]["parent_process"]["cmd_line"] = "A" * 20_000

    response = post_triage(data)

    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "command_line"


def test_realistic_large_ocsf_alert_fits_the_body_limit():
    data = load("ocsf_clipboard_stager.json")
    # Exports carry lots of vendor detail the adapter ignores.
    data["unmapped"]["observables"] = [{"name": f"field_{i}", "value": "x" * 300} for i in range(100)]
    assert 32 * 1024 < len(json.dumps(data)) < main.MAX_BODY_BYTES

    assert post_triage(data).status_code == 200


def test_unknown_source_detection_field_rejected():
    response = post_triage({"hostname": "WS-01", "source_detection": {"title": "x", "score": 9}})

    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "source_detection.score"


def test_deeply_nested_json_is_rejected_cleanly():
    # Just under the size limit. Depending on the Python build, json.loads either
    # parses this (then it's not an alert: 422) or hits its recursion limit (400).
    body = b"[" * 32_000 + b"]" * 32_000

    response = client.post("/api/triage", content=body, headers={"Content-Type": "application/json"})

    assert response.status_code in (400, 422)
    assert response.json()["detail"] in ("Request body is not valid JSON", "Invalid alert")


# --- SentinelOne threats and lists of alerts ------------------------------------

def s1_threats() -> list[dict]:
    return load("s1_threat_sample.json")["data"]


@pytest.mark.parametrize("data, expected", [
    ({"hostname": "WS-01"}, "native"),
    (load("ocsf_clipboard_stager.json"), "ocsf"),
    (load("s1_threat_sample.json")["data"][0], "s1_threat"),
])
def test_detected_format_is_returned(data, expected):
    assert post_triage(data).json()["input_format"] == expected


def test_input_format_cannot_be_claimed_by_the_client():
    response = post_triage({"hostname": "WS-01", "input_format": "s1_threat"})

    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "input_format"


def test_single_s1_threat_is_converted_and_triaged():
    body = post_triage(s1_threats()[0]).json()

    assert body["verdict"] == "malicious"
    assert body["alert"]["hostname"] == "WS-FIN-0144"
    assert body["alert"]["source_detection"]["classification"] == "Malware"
    assert body["alert"]["source_detection"]["storyline"] == "5A7C1E0F3B9D2468"
    assert "severity" not in body["alert"]["source_detection"]  # S1 threats don't send one.


def test_s1_api_response_returns_one_result_per_threat_in_order():
    response = post_triage(load("s1_threat_sample.json"))

    assert response.status_code == 200
    body = response.json()
    assert [r["alert"]["hostname"] for r in body] == ["WS-FIN-0144", "WS-ENG-0207", "SRV-LAB-0003"]
    # The invoice's hash isn't looked up in demo mode, and running from Downloads
    # is context only, so demo calls it clean even though the EDR says Trojan.
    assert [r["verdict"] for r in body] == ["malicious", "clean", "malicious"]
    assert {r["input_format"] for r in body} == {"s1_threat"}


def test_plain_list_of_mixed_formats():
    alerts = [{"hostname": "WS-01"}, load("ocsf_clipboard_stager.json"), s1_threats()[2]]

    body = post_triage(alerts).json()

    assert [r["input_format"] for r in body] == ["native", "ocsf", "s1_threat"]


def test_list_of_one_still_returns_a_list():
    body = post_triage([{"hostname": "WS-01"}]).json()

    assert isinstance(body, list) and len(body) == 1


def test_list_counts_once_against_the_demo_rate_limit():
    post_triage([{"hostname": f"WS-{i:02}"} for i in range(main.MAX_ALERTS)])

    remaining = [post_triage({"hostname": "WS-01"}).status_code for _ in range(main.triage_limiter.limit)]

    assert remaining == [200] * (main.triage_limiter.limit - 1) + [429]


def test_list_at_the_cap_is_accepted():
    response = post_triage([{"hostname": f"WS-{i:02}"} for i in range(main.MAX_ALERTS)])

    assert response.status_code == 200
    assert len(response.json()) == main.MAX_ALERTS


@pytest.mark.parametrize("wrap", [lambda alerts: alerts, lambda alerts: {"data": alerts}])
def test_list_over_the_cap_is_rejected(wrap):
    response = post_triage(wrap([{"hostname": f"WS-{i:02}"} for i in range(main.MAX_ALERTS + 1)]))

    assert response.status_code == 422
    assert response.json() == {"detail": "Too many alerts: at most 25 per request"}


@pytest.mark.parametrize("data", [[], {"data": []}])
def test_empty_list_is_rejected(data):
    response = post_triage(data)

    assert response.status_code == 422
    assert response.json() == {"detail": "The list has no alerts in it"}


def test_invalid_alert_in_a_list_is_named_by_index():
    response = post_triage([{"hostname": "WS-01"}, {"hostname": "WS-02", "pid": 4}, "not an alert"])

    assert response.status_code == 422
    assert response.json()["errors"] == [{"field": "[1].pid", "message": "Extra inputs are not permitted"}]


def test_non_object_in_a_list_is_rejected():
    response = post_triage([{"hostname": "WS-01"}, "not an alert"])

    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "[1]"


def test_s1_strict_caps_apply_after_conversion():
    data = s1_threats()[0]
    data["threatInfo"]["classification"] = "C" * 100

    response = post_triage(data)

    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "source_detection.classification"


def test_too_many_indicators_rejected_for_native_input():
    detection = {"title": "x", "indicators": ["y"] * 26}

    response = post_triage({"hostname": "WS-01", "source_detection": detection})

    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "source_detection.indicators"


def test_live_list_is_charged_once_per_alert(monkeypatch):
    monkeypatch.setenv("ALLOW_LIVE", "1")
    two = [{"hostname": "WS-01"}, {"hostname": "WS-02"}]  # No indicators, so nothing to call.

    assert post_triage(two, live=True).status_code == 200
    assert post_triage({"hostname": "WS-03"}, live=True).status_code == 429


def test_live_list_over_the_live_limit_is_refused_without_spending_budget(monkeypatch):
    monkeypatch.setenv("ALLOW_LIVE", "1")
    three = [{"hostname": f"WS-{i}"} for i in range(main.live_limiter.limit + 1)]

    response = post_triage(three, live=True)

    assert response.status_code == 422
    assert response.json() == {"detail": "Live lookups take at most 2 alerts per request"}
    assert post_triage({"hostname": "WS-01"}, live=True).status_code == 200


def test_rate_limiter_cost():
    now = [0.0]
    limiter = RateLimiter(limit=3, window_seconds=60, clock=lambda: now[0])

    assert limiter.check("a", cost=2) is None
    now[0] = 10.0
    assert limiter.check("a", cost=2) == 50  # Waits for the two hits at t=0 to expire.
    assert limiter.check("a") is None  # One hit still fits.
    assert limiter.check("a", cost=5) == 60  # More than the limit: never allowed, but never raises.
    assert RateLimiter(limit=1).check("b", cost=2) == 60
