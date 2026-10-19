"""Convert an OCSF-style EDR alert into our Alert model.

OCSF (Open Cybersecurity Schema Framework) Detection Findings are what some
EDRs, SentinelOne among them, export. The parts used here:

    finding_info.title / .analytic.name     → source_detection (the EDR's own view)
    severity, or severity_id                → source_detection.severity
    evidences[].process.file.path / .name   → file_path
    evidences[].process.file.hashes[]       → sha256 (the entry with algorithm_id 3)
    evidences[].process.cmd_line            → command_line
    evidences[].process.parent_process      → parent_process (its image path), and
                                              its cmd_line when the process has none
    evidences[].process.user, actor.user    → user, as DOMAIN\\name
    device.hostname / .name, resources[]    → hostname

A detection on a written file (a dropped .ps1, say) usually has no command
line of its own; the interesting command line is the parent's, the process
that wrote or ran it. That's why command_line falls back to the parent.

Exports vary between vendors and versions, so every field is optional:
anything missing, empty, or the wrong type becomes None. to_alert() never
raises on unexpected shapes.
"""

import re

from models import Alert, SourceDetection

SHA256_ALGORITHM_ID = 3  # OCSF Fingerprint algorithm_id for SHA-256.

# OCSF severity_id labels, for exports that only send the number.
SEVERITY_LABELS = {
    0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium",
    4: "High", 5: "Critical", 6: "Fatal", 99: "Other",
}

# Hostname to use when the export has none. Alert requires one, and the
# behavior findings are still worth having without it.
UNKNOWN_HOST = "(unknown host)"

# Kernel-style paths: \Device\HarddiskVolume3\Windows\... The volume-to-letter
# mapping isn't in the alert, so assume C:, which is right for the system drive.
DEVICE_PATH_PATTERN = re.compile(r"\\Device\\HarddiskVolume\d+\\", re.IGNORECASE)


def is_ocsf(data: object) -> bool:
    """True if this JSON looks like an OCSF finding rather than one of our alerts."""
    return isinstance(data, dict) and "finding_info" in data and "evidences" in data


def to_alert(data: dict) -> Alert:
    """Map an OCSF finding onto an Alert. Never raises; missing parts become None."""
    process = _first_process(data)
    file = _dict(process.get("file"))
    parent = _dict(process.get("parent_process"))

    return Alert(
        hostname=_hostname(data) or UNKNOWN_HOST,
        user=_user(_dict(process.get("user"))) or _user(_dict(_dict(data.get("actor")).get("user"))),
        sha256=_sha256(file.get("hashes")),
        file_path=_path(file.get("path")) or _text(file.get("name")),
        command_line=_path(process.get("cmd_line")) or _path(parent.get("cmd_line")),
        parent_process=_path(_dict(parent.get("file")).get("path")) or _text(_dict(parent.get("file")).get("name")),
        source_detection=_source_detection(data),
    )


def normalize_device_path(text: str) -> str:
    r"""\Device\HarddiskVolume3\Windows\x.exe → C:\Windows\x.exe, anywhere in the text."""
    return DEVICE_PATH_PATTERN.sub(lambda _: "C:\\", text)  # A function, so the backslash isn't an escape.


# --- Field helpers ------------------------------------------------------------

def _dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _text(value: object) -> str | None:
    """A non-empty, stripped string, or None for anything else."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _path(value: object) -> str | None:
    text = _text(value)
    return normalize_device_path(text) if text else None


def _first_process(data: dict) -> dict:
    """The process of the first evidence that has one."""
    evidences = data.get("evidences")
    if not isinstance(evidences, list):
        return {}
    for evidence in evidences:
        process = _dict(_dict(evidence).get("process"))
        if process:
            return process
    return {}


def _sha256(hashes: object) -> str | None:
    if not isinstance(hashes, list):
        return None
    for entry in hashes:
        entry = _dict(entry)
        if entry.get("algorithm_id") == SHA256_ALGORITHM_ID and _text(entry.get("value")):
            return _text(entry["value"]).lower()
    return None


def _user(user: dict) -> str | None:
    """'LAB\\m.ortiz' from {"name": "m.ortiz", "domain": "LAB"}, or the name as given."""
    name = _text(user.get("name"))
    if name is None:
        return None
    domain = _text(user.get("domain"))
    if domain and "\\" not in name:
        return f"{domain}\\{name}"
    return name


def _hostname(data: dict) -> str | None:
    device = _dict(data.get("device"))
    hostname = _text(device.get("hostname")) or _text(device.get("name"))
    if hostname:
        return hostname
    # Some exports only name the endpoint in resources[].
    resources = data.get("resources")
    if isinstance(resources, list):
        for resource in resources:
            name = _text(_dict(resource).get("name"))
            if name:
                return name
    return None


def _source_detection(data: dict) -> SourceDetection | None:
    info = _dict(data.get("finding_info"))
    severity = _text(data.get("severity"))
    if severity is None and isinstance(data.get("severity_id"), int):
        severity = SEVERITY_LABELS.get(data["severity_id"])

    detection = SourceDetection(
        title=_text(info.get("title")),
        severity=severity,
        analytic=_text(_dict(info.get("analytic")).get("name")),
    )
    if detection == SourceDetection():
        return None  # The EDR said nothing we can show.
    return detection
