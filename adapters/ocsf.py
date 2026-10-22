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

from adapters.common import UNKNOWN_HOST, as_dict, normalize_device_path, path, sha256, text
from models import Alert, SourceDetection

__all__ = ["UNKNOWN_HOST", "is_ocsf", "normalize_device_path", "to_alert"]

SHA256_ALGORITHM_ID = 3  # OCSF Fingerprint algorithm_id for SHA-256.

# OCSF severity_id labels, for exports that only send the number.
SEVERITY_LABELS = {
    0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium",
    4: "High", 5: "Critical", 6: "Fatal", 99: "Other",
}


def is_ocsf(data: object) -> bool:
    """True if this JSON looks like an OCSF finding rather than one of our alerts."""
    return isinstance(data, dict) and "finding_info" in data and "evidences" in data


def to_alert(data: dict) -> Alert:
    """Map an OCSF finding onto an Alert. Never raises; missing parts become None."""
    process = _first_process(data)
    file = as_dict(process.get("file"))
    parent = as_dict(process.get("parent_process"))

    return Alert(
        hostname=_hostname(data) or UNKNOWN_HOST,
        user=_user(as_dict(process.get("user"))) or _user(as_dict(as_dict(data.get("actor")).get("user"))),
        sha256=_sha256_entry(file.get("hashes")),
        file_path=path(file.get("path")) or text(file.get("name")),
        command_line=path(process.get("cmd_line")) or path(parent.get("cmd_line")),
        parent_process=path(as_dict(parent.get("file")).get("path")) or text(as_dict(parent.get("file")).get("name")),
        source_detection=_source_detection(data),
    )


# --- Field helpers ------------------------------------------------------------

def _first_process(data: dict) -> dict:
    """The process of the first evidence that has one."""
    evidences = data.get("evidences")
    if not isinstance(evidences, list):
        return {}
    for evidence in evidences:
        process = as_dict(as_dict(evidence).get("process"))
        if process:
            return process
    return {}


def _sha256_entry(hashes: object) -> str | None:
    if not isinstance(hashes, list):
        return None
    for entry in hashes:
        entry = as_dict(entry)
        if entry.get("algorithm_id") == SHA256_ALGORITHM_ID and text(entry.get("value")):
            return sha256(entry["value"])
    return None


def _user(user: dict) -> str | None:
    """'LAB\\m.ortiz' from {"name": "m.ortiz", "domain": "LAB"}, or the name as given."""
    name = text(user.get("name"))
    if name is None:
        return None
    domain = text(user.get("domain"))
    if domain and "\\" not in name:
        return f"{domain}\\{name}"
    return name


def _hostname(data: dict) -> str | None:
    device = as_dict(data.get("device"))
    hostname = text(device.get("hostname")) or text(device.get("name"))
    if hostname:
        return hostname
    # Some exports only name the endpoint in resources[].
    resources = data.get("resources")
    if isinstance(resources, list):
        for resource in resources:
            name = text(as_dict(resource).get("name"))
            if name:
                return name
    return None


def _source_detection(data: dict) -> SourceDetection | None:
    info = as_dict(data.get("finding_info"))
    severity = text(data.get("severity"))
    if severity is None and isinstance(data.get("severity_id"), int):
        severity = SEVERITY_LABELS.get(data["severity_id"])

    detection = SourceDetection(
        title=text(info.get("title")),
        severity=severity,
        analytic=text(as_dict(info.get("analytic")).get("name")),
    )
    if detection == SourceDetection():
        return None  # The EDR said nothing we can show.
    return detection
