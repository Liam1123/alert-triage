"""Behavioral analysis: match an alert's process details against ATT&CK-mapped rules.

Pure logic: no network, no cache, no printing. analyze() never raises.
"""

import base64
import binascii
import re
from pathlib import Path, PureWindowsPath

import attack
from models import Alert, BehaviorFinding, Severity, Verdict, VERDICT_RANK
from rules import Rule, load_rules

# How each rule severity affects the verdict. Low findings are listed for
# context (they're also common in normal admin work) but don't change it.
SEVERITY_VERDICT: dict[Severity, Verdict | None] = {
    "high": "malicious",
    "medium": "suspicious",
    "low": None,
}

# Escalation: this many *different* medium rules on one alert → malicious.
# One medium finding (an encoded command, a new scheduled task) has plenty of
# legitimate explanations. Several together, like encoded PowerShell that
# also creates a Run key, look like an intrusion chain, not a coincidence.
# Counted by rule id, so one rule matching both the raw and decoded command
# only counts once.
ESCALATION_MEDIUM_COUNT = 2

RULES_PATH = Path(__file__).parent / "rules" / "behavior_rules.yaml"

# Loaded once at import. A malformed rules file raises RuleError right here,
# at startup, rather than during triage.
RULES: list[Rule] = load_rules(RULES_PATH)

# Limits that keep regex matching and decoding fast and bounded.
MAX_TEXT_CHARS = 8_192  # Per field, before matching.
MAX_ENCODED_CHARS = 16_384  # Base64 characters we're willing to decode.
MAX_DECODED_CHARS = 8_192  # Decoded text kept for the result and for matching.

# Finds the base64 argument to -EncodedCommand (or an abbreviation). This
# mirrors the encoded_powershell rule; it's in code because decoding is code.
POWERSHELL_PATTERN = re.compile(r"\b(powershell|pwsh)(\.exe)?\b", re.IGNORECASE)
ENCODED_ARGUMENT_PATTERN = re.compile(
    r"(?<!\S)[-/–—―]"
    r"(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom"
    r"|encodedcomm|encodedcomma|encodedcomman|encodedcommand)"
    r"\s+[\"']?([a-z0-9+/=]{16,})",
    re.IGNORECASE,
)


def analyze(alert: Alert, rules: list[Rule] | None = None) -> list[BehaviorFinding]:
    """Run every rule against the alert, then against any decoded PowerShell."""
    if rules is None:
        rules = RULES

    findings = _run_rules(rules, _fields_for(alert), from_decoded=False)

    decoded = decode_encoded_command(alert.command_line)
    if decoded:
        # The decoded text is a PowerShell script, so it's only a command line.
        # Rules about parents or file paths can't match it, which is correct.
        decoded_fields = {"command_line": deobfuscate(decoded)}
        findings += _run_rules(rules, decoded_fields, from_decoded=True)

    return findings


def has_behavior_data(alert: Alert) -> bool:
    """True if the alert has anything for behavior rules to look at."""
    return bool(alert.command_line or alert.file_path or alert.parent_process)


def behavior_verdict(findings: list[BehaviorFinding]) -> Verdict:
    """Combine findings into one verdict: worst severity wins, plus escalation."""
    verdicts = [SEVERITY_VERDICT[f.severity] for f in findings]
    verdicts = [v for v in verdicts if v is not None]
    if escalation_applies(findings):
        verdicts.append("malicious")
    if not verdicts:
        return "clean"
    return max(verdicts, key=lambda verdict: VERDICT_RANK[verdict])


def escalation_applies(findings: list[BehaviorFinding]) -> bool:
    medium_rules = {f.rule_id for f in findings if f.severity == "medium"}
    return len(medium_rules) >= ESCALATION_MEDIUM_COUNT


def deobfuscate(text: str) -> str:
    """Undo simple cmd.exe obfuscation so rules see what actually runs.

    - Carets are cmd's escape character: p^ow^er^shell runs powershell.
    - Empty quote pairs vanish when cmd parses: pow""ershell runs powershell.
    - Repeated whitespace is collapsed to one space.
    """
    text = text.replace("^", "")
    text = text.replace('""', "")
    return re.sub(r"\s+", " ", text).strip()


def decode_encoded_command(command_line: str | None) -> str | None:
    """Decode a PowerShell -EncodedCommand argument, or return None.

    PowerShell expects base64 of UTF-16LE text. If that doesn't produce
    readable text, try UTF-8 (some tools encode it that way). If neither
    works, give up and return None. Nothing is ever executed.
    """
    if not command_line:
        return None
    # Search the whole command line (Windows caps it at 32,767 characters, and
    # these two patterns run in linear time). Only the base64 blob is capped,
    # so truncation is detected and marked instead of happening silently.
    text = deobfuscate(command_line)
    if not POWERSHELL_PATTERN.search(text):
        return None
    found = ENCODED_ARGUMENT_PATTERN.search(text)
    if found is None:
        return None

    blob = found.group(2)
    truncated = len(blob) > MAX_ENCODED_CHARS
    if truncated:
        blob = blob[:MAX_ENCODED_CHARS]  # A multiple of 4, so still valid base64.
    else:
        blob += "=" * (-len(blob) % 4)  # Restore padding if it was left off.

    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None

    decoded = _bytes_to_text(raw)
    if decoded is None:
        return None
    if truncated or len(decoded) > MAX_DECODED_CHARS:
        decoded = decoded[:MAX_DECODED_CHARS] + "\n[truncated]"
    return decoded


def _bytes_to_text(raw: bytes) -> str | None:
    """Decode as UTF-16LE, falling back to UTF-8. None if neither looks like text."""
    for encoding in ("utf-16-le", "utf-8"):
        data = raw
        if encoding == "utf-16-le" and len(data) % 2:
            data = data[:-1]  # Truncated input can end mid-character.
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _looks_like_text(text):
            return text.replace("\x00", "")
    return None


def _looks_like_text(text: str) -> bool:
    """Mostly printable ASCII? Wrong-encoding garbage usually isn't."""
    if not text.strip():
        return False
    readable = sum(1 for ch in text if (32 <= ord(ch) < 127) or ch in "\r\n\t")
    return readable / len(text) >= 0.9


def _fields_for(alert: Alert) -> dict[str, str]:
    """The text each rule condition can look at, deobfuscated and length-capped."""
    fields = {}
    for name in ("command_line", "file_path", "parent_process"):
        value = getattr(alert, name)
        if value:
            fields[name] = deobfuscate(value[:MAX_TEXT_CHARS])

    image = _image_name(fields.get("file_path"), fields.get("command_line"))
    if image:
        fields["image"] = image
    return fields


def _image_name(file_path: str | None, command_line: str | None) -> str | None:
    """The process's file name: from file_path, else the command line's first token."""
    if file_path:
        return PureWindowsPath(file_path).name
    if command_line:
        if command_line.startswith('"'):
            program = command_line[1:].split('"', 1)[0]
        else:
            program = command_line.split(" ", 1)[0]
        return PureWindowsPath(program).name or None
    return None


def _run_rules(rules: list[Rule], fields: dict[str, str], from_decoded: bool) -> list[BehaviorFinding]:
    findings = []
    for rule in rules:
        matches = rule.match.evaluate(fields)
        if matches is None:
            continue

        matched_fields = list(dict.fromkeys(m.field for m in matches))  # Unique, in order.
        findings.append(
            BehaviorFinding(
                rule_id=rule.id,
                rule_name=rule.name,
                techniques=[attack.technique(t) for t in rule.techniques],
                severity=rule.severity,
                matched_field=", ".join(matched_fields),
                evidence=" | ".join(m.evidence for m in matches),
                from_decoded=from_decoded,
            )
        )
    return findings
