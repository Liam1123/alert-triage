"""Data models shared by the enrichers, the triage logic, and the CLI.

Everything the project produces is one of these models, so a future FastAPI
backend can return them directly as JSON.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

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
    problem), `error` explains why and the count fields are left as None.
    """

    source: str
    indicator: str
    indicator_type: IndicatorType
    malicious_count: int | None = None
    total_engines: int | None = None
    first_seen: datetime | None = None
    permalink: str | None = None
    error: str | None = None


class TriageResult(BaseModel):
    """The final output: the original alert, what we learned, and a verdict."""

    alert: Alert
    enrichments: list[EnrichmentResult]
    verdict: Verdict
    reasons: list[str]
