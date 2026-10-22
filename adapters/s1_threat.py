"""Convert a SentinelOne threat (the console's and API's legacy JSON) into our Alert.

This is the shape the console's threat export and GET /web/api/v2.1/threats
return, not OCSF. The parts used here:

    agentRealtimeInfo.agentComputerName,
      else agentDetectionInfo.agentComputerName  → hostname
    threatInfo.processUser                       → user (already DOMAIN\\name)
    threatInfo.sha256                            → sha256
    threatInfo.filePath                          → file_path
    threatInfo.originalFileName                  → original_file_name (see ORIGINAL_NAME_KEY)
    threatInfo.maliciousProcessArguments         → command_line
    threatInfo.originatorProcess                 → parent_process (a process name)
    threatInfo.threatName, .classification,
      .confidenceLevel, .detectionEngines/.engines,
      .storyline, and indicators[]               → source_detection (the EDR's own view)

The API wraps threats as {"data": [...], "pagination": {...}}; unwrap()
returns the list inside, and each item is converted on its own.

As with OCSF, every field is optional: anything missing, empty, or the wrong
type becomes None, and to_alert() never raises on unexpected shapes.
"""

from adapters.common import UNKNOWN_HOST, as_dict, as_list, path, sha256, text
from models import Alert, SourceDetection

# The vendor's indicators are shown for context only. Real threats can carry
# dozens with long descriptions, so keep the first few, shortened. The strict
# API model caps the list at 25 items of 256 characters; these stay inside it.
MAX_INDICATORS = 10
MAX_INDICATOR_LENGTH = 200

# The PE OriginalFileName. Not confirmed against SentinelOne's API reference:
# check the key name in a real threat and change it here if needed.
ORIGINAL_NAME_KEY = "originalFileName"


def is_s1_threat(data: object) -> bool:
    """True if this JSON looks like one SentinelOne threat."""
    return isinstance(data, dict) and isinstance(data.get("threatInfo"), dict)


def unwrap(data: object) -> list | None:
    """The threats in an API response ({"data": [...]}), or None if it isn't one."""
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        return data["data"]
    return None


def to_alert(data: dict) -> Alert:
    """Map a SentinelOne threat onto an Alert. Never raises; missing parts become None."""
    info = as_dict(data.get("threatInfo"))
    realtime = as_dict(data.get("agentRealtimeInfo"))
    detection = as_dict(data.get("agentDetectionInfo"))

    return Alert(
        hostname=text(realtime.get("agentComputerName")) or text(detection.get("agentComputerName")) or UNKNOWN_HOST,
        user=text(info.get("processUser")),
        sha256=sha256(info.get("sha256")),
        file_path=path(info.get("filePath")),
        original_file_name=text(info.get(ORIGINAL_NAME_KEY)),
        command_line=path(info.get("maliciousProcessArguments")),
        parent_process=path(info.get("originatorProcess")),
        source_detection=_source_detection(info, data.get("indicators")),
    )


# --- Field helpers ------------------------------------------------------------

def _source_detection(info: dict, indicators: object) -> SourceDetection | None:
    detection = SourceDetection(
        title=text(info.get("threatName")),
        classification=text(info.get("classification")),
        confidence=text(info.get("confidenceLevel")),
        analytic=_engines(info),
        storyline=text(info.get("storyline")),
        indicators=_indicators(indicators),
    )
    if detection == SourceDetection():
        return None  # The EDR said nothing we can show.
    return detection


def _engines(info: dict) -> str | None:
    """'On-Write Static AI, SentinelOne Cloud' from detectionEngines[].title, else engines[]."""
    names = [text(as_dict(engine).get("title")) for engine in as_list(info.get("detectionEngines"))]
    if not any(names):
        names = [text(engine) for engine in as_list(info.get("engines"))]
    return ", ".join(name for name in names if name) or None


def _indicators(indicators: object) -> list[str]:
    """'Evasion: Suspicious use of a char-shift loop' for each indicator, the first few only."""
    found = []
    for indicator in as_list(indicators):
        indicator = as_dict(indicator)
        category, description = text(indicator.get("category")), text(indicator.get("description"))
        line = f"{category}: {description}" if category and description else category or description
        if line:
            found.append(_shorten(line))
        if len(found) == MAX_INDICATORS:
            break
    return found


def _shorten(line: str) -> str:
    return line if len(line) <= MAX_INDICATOR_LENGTH else line[: MAX_INDICATOR_LENGTH - 1] + "…"
