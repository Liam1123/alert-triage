"""Tests for the OCSF adapter (adapters/ocsf.py) and format auto-detection."""

import json
from pathlib import Path

import httpx
import pytest
import respx

import adapters
import cli
from adapters import ocsf
from models import Alert, SourceDetection
from triage import triage

ALERTS_DIR = Path(__file__).parent.parent / "alerts"
SAMPLE = ALERTS_DIR / "ocsf_clipboard_stager.json"
SAMPLE_SHA256 = "1edef41aedb08e1ea7558e6950d91fca5f831923ce6f10ba4173c98a0562412b"
PAYLOAD = "Add-Type -AssemblyName System.Windows.Forms; iex ([Windows.Forms.Clipboard]::GetText())"


def load_sample() -> dict:
    return json.loads(SAMPLE.read_text())


def finding(**process) -> dict:
    """A minimal OCSF finding with one evidence process."""
    return {"finding_info": {}, "evidences": [{"process": process}], "device": {"hostname": "WS-TEST-01"}}


# --- The fictional sample ------------------------------------------------------

def test_sample_converts_to_expected_alert():
    alert = ocsf.to_alert(load_sample())

    assert alert == Alert(
        hostname="WS-FIN-0112",
        user="LAB\\m.ortiz",
        sha256=SAMPLE_SHA256,
        file_path=r"C:\Users\m.ortiz\AppData\Roaming\Microsoft\Windows\Themes\theme_sync.ps1",
        command_line=alert.command_line,  # Checked separately below.
        parent_process=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        source_detection=SourceDetection(
            title="Unsigned PowerShell script written to Themes folder",
            severity="High",
            analytic="Behavioral Engine: Obfuscated Script Loader",
        ),
    )
    # The .ps1 has no command line of its own, so the parent's is used.
    assert alert.command_line.startswith("powershell.exe -sta ")
    assert "$function:f=$d; f" in alert.command_line


@respx.mock
def test_sample_triage_is_malicious_with_decoded_command():
    respx.get(f"https://www.virustotal.com/api/v3/files/{SAMPLE_SHA256}").mock(return_value=httpx.Response(404))

    result = triage(ocsf.to_alert(load_sample()))

    assert result.verdict == "malicious"
    assert result.shift_decoded_command == PAYLOAD
    assert result.decoded_command is None  # No -EncodedCommand here.
    assert result.alert.source_detection.severity == "High"

    by_rule = {(f.rule_id, f.decoder) for f in result.behavior_findings}
    assert ("char_shift_decoding", None) in by_rule  # The loop in the raw command line.
    assert ("clipboard_execution", "char_shift") in by_rule  # What it decodes to.
    assert any("in char-shift-decoded command" in r for r in result.reasons)
    assert "Execution" in result.tactics and "Stealth" in result.tactics


def test_sample_uses_only_fictional_example_values():
    text = SAMPLE.read_text()
    assert "http" not in text  # No URLs at all; the payload only reads the clipboard.
    assert "Example EDR" in text


# --- Field mapping -------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    (r"\Device\HarddiskVolume3\Windows\System32\cmd.exe", r"C:\Windows\System32\cmd.exe"),
    (r"\device\harddiskvolume12\Users\a\x.exe", r"C:\Users\a\x.exe"),
    (r'cmd.exe /c "\Device\HarddiskVolume2\Temp\a.bat"', r'cmd.exe /c "C:\Temp\a.bat"'),
    (r"C:\Windows\explorer.exe", r"C:\Windows\explorer.exe"),
    (r"\Device\Mup\server\share\a.exe", r"\Device\Mup\server\share\a.exe"),  # Network path: left alone.
])
def test_normalize_device_path(raw, expected):
    assert ocsf.normalize_device_path(raw) == expected


def test_sha256_is_the_algorithm_3_entry_lowercased():
    alert = ocsf.to_alert(finding(file={"hashes": [
        {"algorithm_id": 1, "value": "d41d8cd98f00b204e9800998ecf8427e"},
        {"algorithm_id": 3, "value": "  " + "AB" * 32 + " "},
    ]}))

    assert alert.sha256 == "ab" * 32


def test_no_sha256_without_an_algorithm_3_entry():
    alert = ocsf.to_alert(finding(file={"hashes": [{"algorithm": "SHA-256", "value": "ab" * 32}]}))

    assert alert.sha256 is None


def test_process_command_line_is_preferred_over_parent():
    alert = ocsf.to_alert(finding(cmd_line="child.exe --run", parent_process={"cmd_line": "parent.exe"}))

    assert alert.command_line == "child.exe --run"


def test_file_name_is_used_when_there_is_no_path():
    alert = ocsf.to_alert(finding(file={"name": "dropper.ps1"}, parent_process={"file": {"name": "wscript.exe"}}))

    assert alert.file_path == "dropper.ps1"
    assert alert.parent_process == "wscript.exe"


@pytest.mark.parametrize("data, expected", [
    (finding(user={"name": "m.ortiz", "domain": "LAB"}), "LAB\\m.ortiz"),
    (finding(user={"name": "LAB\\m.ortiz", "domain": "LAB"}), "LAB\\m.ortiz"),
    (finding(user={"name": "m.ortiz"}), "m.ortiz"),
    ({**finding(), "actor": {"user": {"name": "svc_lab", "domain": "LAB"}}}, "LAB\\svc_lab"),
    (finding(user={"domain": "LAB"}), None),
])
def test_user(data, expected):
    assert ocsf.to_alert(data).user == expected


@pytest.mark.parametrize("extra, expected", [
    ({"device": {"name": "WS-NAME-01"}}, "WS-NAME-01"),
    ({"device": {}, "resources": [{"type": "Endpoint"}, {"name": "WS-RES-01"}]}, "WS-RES-01"),
    ({"device": None, "resources": "nope"}, ocsf.UNKNOWN_HOST),
])
def test_hostname_fallbacks(extra, expected):
    data = {"finding_info": {}, "evidences": [], **extra}

    assert ocsf.to_alert(data).hostname == expected


def test_severity_id_is_used_when_there_is_no_severity_label():
    data = {"finding_info": {"title": "x"}, "evidences": [], "severity_id": 5}

    assert ocsf.to_alert(data).source_detection.severity == "Critical"


def test_no_source_detection_when_the_edr_said_nothing():
    assert ocsf.to_alert({"finding_info": {}, "evidences": []}).source_detection is None


# --- Malformed and partial input never crashes ---------------------------------

@pytest.mark.parametrize("data", [
    {"finding_info": None, "evidences": None},
    {"finding_info": "title", "evidences": "not a list"},
    {"finding_info": [], "evidences": [None, 7, "x", {"process": "not a dict"}, {"process": []}]},
    {"finding_info": {"analytic": "str", "title": 42}, "evidences": [{"process": {"file": [], "user": "LAB\\x"}}]},
    {"finding_info": {}, "evidences": [{"process": {"file": {"hashes": {"algorithm_id": 3}}}}]},
    {"finding_info": {}, "evidences": [{"process": {"file": {"hashes": [None, {"algorithm_id": 3, "value": 12}]}}}]},
    {"finding_info": {}, "evidences": [{"process": {"cmd_line": "   ", "parent_process": {"file": "x"}}}]},
    {"finding_info": {}, "evidences": [], "severity_id": "high", "severity": ["High"], "device": {"hostname": 99}},
])
def test_malformed_ocsf_gives_an_alert_with_nones(data):
    alert = ocsf.to_alert(data)

    assert alert.hostname == ocsf.UNKNOWN_HOST
    assert alert.sha256 is None
    assert alert.command_line is None
    assert alert.file_path is None
    assert alert.parent_process is None


def test_evidence_without_a_process_is_skipped():
    data = {"finding_info": {}, "evidences": [{"file": {}}, {"process": {"cmd_line": "a.exe"}}]}

    assert ocsf.to_alert(data).command_line == "a.exe"


# --- Auto-detection -------------------------------------------------------------

@pytest.mark.parametrize("data, expected", [
    ({"finding_info": {}, "evidences": []}, True),
    ({"finding_info": {}}, False),
    ({"evidences": []}, False),
    ({"hostname": "WS-01"}, False),
    ([{"finding_info": {}, "evidences": []}], False),
    ("finding_info evidences", False),
])
def test_is_ocsf(data, expected):
    assert ocsf.is_ocsf(data) is expected


def test_alert_fields_passes_our_own_alerts_through_unchanged():
    data = {"hostname": "WS-01", "anything": "kept for the caller's validation"}

    assert adapters.alert_fields(data) is data


def test_alert_fields_converts_ocsf():
    fields = adapters.alert_fields(load_sample())

    assert fields["hostname"] == "WS-FIN-0112"
    assert fields["source_detection"]["severity"] == "High"
    assert "remote_ip" not in fields  # None values are left out.


@respx.mock
def test_cli_accepts_ocsf(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_dotenv", lambda: None)  # Never read .env in tests.
    monkeypatch.setattr("sys.argv", ["cli.py", str(SAMPLE)])
    respx.get(url__startswith="https://www.virustotal.com/").mock(return_value=httpx.Response(404))

    assert cli.main() == 0

    out = capsys.readouterr().out
    assert "VERDICT: MALICIOUS" in out
    assert "EDR said: Unsigned PowerShell script written to Themes folder (High," in out
    assert PAYLOAD in out
    assert "(in char-shift-decoded command)" in out
