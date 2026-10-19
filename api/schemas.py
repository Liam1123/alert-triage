"""The request model for POST /api/triage.

It is the same Alert the CLI uses, made strict for untrusted input: unknown
fields are rejected and every string has a length cap. The caps are generous
for real EDR data and well under the 32 KB body limit in main.py.
"""

from typing import Annotated

from pydantic import ConfigDict, StringConstraints

from models import Alert

Short = Annotated[str, StringConstraints(max_length=256)]
Path = Annotated[str, StringConstraints(max_length=1_024)]
# Windows caps a command line at 32,767 characters, but the body limit is 32 KB
# in total, so this is the realistic maximum for one field.
CommandLine = Annotated[str, StringConstraints(max_length=16_384)]


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

    def to_alert(self) -> Alert:
        """The plain Alert the core expects (so the response has no request-only config)."""
        return Alert.model_validate(self.model_dump())
