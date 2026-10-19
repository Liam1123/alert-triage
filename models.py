"""Data models shared by the enrichers, the triage logic, and the CLI.

Everything the project produces is one of these models, so a future FastAPI
backend can return them directly as JSON.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["malicious", "suspicious", "clean", "unknown"]
IndicatorType = Literal["sha256", "ip", "domain"]


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


class TriageResult(BaseModel):
    """The final output: the original alert, what we learned, and a verdict."""

    alert: Alert
    enrichments: list[EnrichmentResult]
    verdict: Verdict
    reasons: list[str]
