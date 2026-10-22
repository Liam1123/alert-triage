"""Adapters turn other alert formats into our Alert's fields.

The CLI and the API call these:

    split(data)          the alerts in a list or a SentinelOne {"data": [...]}
                         response, or None for a single alert
    detect_format(item)  "ocsf", "s1_threat" or "native"
    alert_fields(item)   OCSF findings and SentinelOne threats converted,
                         anything else returned as-is

Either way the caller validates the result with its own model (Alert in the
CLI, the strict AlertRequest in the API), so the API's limits apply after
conversion too.
"""

from adapters import ocsf, s1_threat
from models import InputFormat


def split(data: object) -> list | None:
    """The alerts if `data` holds several; None if it is a single alert."""
    if isinstance(data, list):
        return data
    return s1_threat.unwrap(data)


def detect_format(data: object) -> InputFormat:
    if ocsf.is_ocsf(data):
        return "ocsf"
    if s1_threat.is_s1_threat(data):
        return "s1_threat"
    return "native"


def alert_fields(data: object) -> object:
    """Our alert's fields as a dict if `data` is a known vendor format; otherwise `data` unchanged."""
    match detect_format(data):
        case "ocsf":
            return ocsf.to_alert(data).model_dump(exclude_none=True)
        case "s1_threat":
            return s1_threat.to_alert(data).model_dump(exclude_none=True)
        case _:
            return data
