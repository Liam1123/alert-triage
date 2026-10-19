"""The request model for POST /api/triage.

It is the same Alert the CLI uses, made strict for untrusted input: unknown
fields are rejected and every string has a length cap. The caps are generous
for real EDR data. OCSF alerts are converted to these fields first
(adapters/), so the same checks apply to them after conversion.
"""

from typing import Annotated

from pydantic import ConfigDict, StringConstraints

from models import Alert, SourceDetection

Short = Annotated[str, StringConstraints(max_length=256)]
Path = Annotated[str, StringConstraints(max_length=1_024)]
# Windows caps a command line at 32,767 characters; half that is plenty for
# real alerts and keeps one field well inside the body limit in main.py.
CommandLine = Annotated[str, StringConstraints(max_length=16_384)]


class SourceDetectionRequest(SourceDetection):
    model_config = ConfigDict(extra="forbid")

    title: Short | None = None
    severity: Annotated[str, StringConstraints(max_length=64)] | None = None
    analytic: Short | None = None


class AlertRequest(Alert):
    model_config = ConfigDict(extra="forbid")

    hostname: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    user: Short | None = None
    sha256: Annotated[str, StringConstraints(max_length=128)] | None = None
    file_path: Path | None = None
    command_line: CommandLine | None = None
    parent_process: Path | None = None
    remote_ip: Annotated[str, StringConstraints(max_length=64)] | None = None
    domain: Short | None = None
    source_detection: SourceDetectionRequest | None = None

    def to_alert(self) -> Alert:
        """The plain Alert the core expects (so the response has no request-only config)."""
        return Alert.model_validate(self.model_dump())
