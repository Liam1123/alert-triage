"""Data models shared by the enrichers, the triage logic, and the CLI.

Everything the project produces is one of these models, so a future FastAPI
backend can return them directly as JSON.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_serializer

Verdict = Literal["malicious", "suspicious", "clean", "unknown"]
IndicatorType = Literal["sha256", "ip", "domain"]
Severity = Literal["low", "medium", "high"]
# Which decoder produced the text a behavior finding matched, if any.
Decoder = Literal["encoded_command", "char_shift"]
# The shape an alert arrived in, as detected by adapters.detect_format().
InputFormat = Literal["native", "ocsf", "s1_threat"]

# Higher number = worse. The overall verdict is the worst individual verdict.
# "unknown" outranks "clean": if we couldn't check something, we can't call
# the whole alert clean.
VERDICT_RANK: dict[Verdict, int] = {"clean": 0, "unknown": 1, "suspicious": 2, "malicious": 3}


class SourceDetection(BaseModel):
    """What the EDR itself said about the alert, kept for context.

    Filled in by an adapter from the vendor's own words: title, severity and
    analytic from OCSF (adapters/ocsf.py); title, classification, confidence,
    engines, storyline and indicators from a SentinelOne threat
    (adapters/s1_threat.py). It never affects our verdict.
    """

    title: str | None = None
    severity: str | None = None
    analytic: str | None = None
    classification: str | None = None  # e.g. "Malware", "Ransomware".
    confidence: str | None = None  # The vendor's confidence level, e.g. "malicious".
    storyline: str | None = None  # SentinelOne's ID for the chain of related events.
    indicators: list[str] = []  # The vendor's own indicator descriptions.

    @model_serializer(mode="wrap")
    def _only_what_the_edr_said(self, handler):
        # Each vendor fills different fields; leaving the empty ones out keeps
        # an OCSF detection looking like an OCSF detection in the JSON.
        return {name: value for name, value in handler(self).items() if value not in (None, [])}


class Alert(BaseModel):
    """An EDR-style alert. Only hostname is required."""

    hostname: str
    user: str | None = None
    sha256: str | None = None
    file_path: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    remote_ip: str | None = None
    domain: str | None = None
    source_detection: SourceDetection | None = None


class EnrichmentResult(BaseModel):
    """The result of looking up one indicator in one threat intel source.

    If the lookup failed (not found, rate limited, no API key, network
    problem), `error` explains why and the data fields are left as None.
    If the indicator was deliberately not looked up (e.g. a private IP),
    `skip_reason` explains why.
    """

    source: str
    indicator: str
    indicator_type: IndicatorType

    # VirusTotal-style results: how many engines flagged the indicator.
    malicious_count: int | None = None
    total_engines: int | None = None
    first_seen: datetime | None = None

    # AbuseIPDB-style results: a 0-100 confidence score and report count.
    score: int | None = Field(default=None, ge=0, le=100)
    report_count: int | None = None

    permalink: str | None = None
    error: str | None = None
    skip_reason: str | None = None

    # True if this result came from the local cache instead of a live API call.
    cached: bool = False

    # Filled in by triage(), not by the enrichers.
    verdict: Verdict | None = None

    def succeeded(self) -> bool:
        """True if the lookup actually returned data (not an error or skip)."""
        return self.error is None and self.skip_reason is None


class Technique(BaseModel):
    """A MITRE ATT&CK technique, e.g. T1059.001 (PowerShell)."""

    id: str
    name: str
    tactics: list[str] = []


class BehaviorFinding(BaseModel):
    """One behavior rule that matched the alert's process details."""

    rule_id: str
    rule_name: str
    techniques: list[Technique]
    severity: Severity
    matched_field: str  # e.g. "command_line", or "parent_process, image"
    evidence: str  # The text that matched, with a little context.
    # (start, end) character offsets in `evidence` of the text the rules matched.
    highlights: list[tuple[int, int]] = []
    from_decoded: bool = False  # True if it matched decoded text, not the raw alert.
    decoder: Decoder | None = None  # Which decoder produced that text.


class TriageResult(BaseModel):
    """The final output: the original alert, what we learned, and a verdict."""

    alert: Alert
    enrichments: list[EnrichmentResult]
    verdict: Verdict
    reasons: list[str]
    behavior_findings: list[BehaviorFinding] = []
    decoded_command: str | None = None  # From PowerShell -EncodedCommand (base64).
    shift_decoded_command: str | None = None  # From a per-character shift ([char]($c - 3)).
    tactics: list[str] = []  # ATT&CK tactics touched, in kill-chain order.
    # Set by the caller (CLI or API) from adapters.detect_format(); triage() only sees the Alert.
    input_format: InputFormat = "native"
