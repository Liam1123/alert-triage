"""Field helpers shared by the adapters.

Vendor exports vary between products and versions, so the adapters read every
field through these: anything missing, empty, or the wrong type becomes None
(or an empty dict/list) instead of raising.
"""

import re

# Hostname to use when the export has none. Alert requires one, and the
# behavior findings are still worth having without it.
UNKNOWN_HOST = "(unknown host)"

# Kernel-style paths: \Device\HarddiskVolume3\Windows\... The volume-to-letter
# mapping isn't in the alert, so assume C:, which is right for the system drive.
DEVICE_PATH_PATTERN = re.compile(r"\\Device\\HarddiskVolume\d+\\", re.IGNORECASE)


def normalize_device_path(text: str) -> str:
    r"""\Device\HarddiskVolume3\Windows\x.exe → C:\Windows\x.exe, anywhere in the text."""
    return DEVICE_PATH_PATTERN.sub(lambda _: "C:\\", text)  # A function, so the backslash isn't an escape.


def as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def as_list(value: object) -> list:
    return value if isinstance(value, list) else []


def text(value: object) -> str | None:
    """A non-empty, stripped string, or None for anything else."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def path(value: object) -> str | None:
    """Like text(), with \\Device\\HarddiskVolumeN\\ turned into C:\\."""
    value = text(value)
    return normalize_device_path(value) if value else None


def sha256(value: object) -> str | None:
    """A hash as lowercase text. Whether it's a valid SHA-256 is the enricher's call."""
    value = text(value)
    return value.lower() if value else None
