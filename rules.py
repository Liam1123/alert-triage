"""Behavior rules: the data model, the YAML loader, and the matching logic.

A rule looks like this in rules/behavior_rules.yaml:

    - id: certutil_download
      name: Certutil download or decode
      description: ...
      techniques: [T1105, T1140]
      severity: high
      match:
        all_of:
          - field: command_line
            regex: '\\bcertutil(\\.exe)?\\b'
          - field: command_line
            regex: '[-/](urlcache|decode)\\b'

`match` is a group: `all_of` (every item must match) or `any_of` (at least
one must match). Items are conditions ({field, regex}) or nested groups.
Regexes are always case-insensitive.

A broken rules file is a developer mistake, so load_rules() raises RuleError
with a message naming the rule and the problem.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, NamedTuple

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, field_validator, model_validator

from models import Severity

# The alert data a condition can look at. "image" is the process's file name
# (e.g. "powershell.exe"), worked out from file_path or the command line.
MatchField = Literal["command_line", "file_path", "image", "parent_process"]

# How much context to show around a regex match in the evidence snippet.
EVIDENCE_CONTEXT_CHARS = 25
MAX_EVIDENCE_CHARS = 160


class RuleError(Exception):
    """The rules file is invalid. Raised at load time, never during analysis."""


class Match(NamedTuple):
    field: str
    evidence: str
    # Where the regex matched inside `evidence`, as (start, end) offsets.
    highlight: tuple[int, int] = (0, 0)


class Condition(BaseModel):
    """One check: does `regex` match somewhere in `field`?"""

    model_config = ConfigDict(extra="forbid")

    field: MatchField
    regex: str
    _pattern: re.Pattern = PrivateAttr()

    @field_validator("regex")
    @classmethod
    def regex_must_compile(cls, value: str) -> str:
        try:
            re.compile(value, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"invalid regex {value!r}: {exc}")
        return value

    def model_post_init(self, context) -> None:
        self._pattern = re.compile(self.regex, re.IGNORECASE)

    def evaluate(self, fields: dict[str, str]) -> list[Match] | None:
        text = fields.get(self.field)
        if not text:
            return None
        found = self._pattern.search(text)
        if found is None:
            return None
        evidence, highlight = _snippet(text, found)
        return [Match(self.field, evidence, highlight)]


class MatchGroup(BaseModel):
    """`all_of` or `any_of` a list of conditions and/or nested groups."""

    model_config = ConfigDict(extra="forbid")

    all_of: list[Condition | MatchGroup] | None = Field(default=None, min_length=1)
    any_of: list[Condition | MatchGroup] | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def exactly_one_of_all_or_any(self) -> MatchGroup:
        if (self.all_of is None) == (self.any_of is None):
            raise ValueError("a match group needs exactly one of 'all_of' or 'any_of'")
        return self

    def evaluate(self, fields: dict[str, str]) -> list[Match] | None:
        """Return the matches that satisfied the group, or None if it didn't match."""
        if self.all_of is not None:
            matches: list[Match] = []
            for item in self.all_of:
                item_matches = item.evaluate(fields)
                if item_matches is None:
                    return None
                matches.extend(item_matches)
            return matches

        for item in self.any_of:
            item_matches = item.evaluate(fields)
            if item_matches is not None:
                return item_matches  # The first item that matched is the evidence.
        return None


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9_]+$")
    name: str
    description: str
    techniques: list[str] = Field(min_length=1)
    severity: Severity
    match: MatchGroup

    @field_validator("techniques")
    @classmethod
    def technique_ids_look_valid(cls, ids: list[str]) -> list[str]:
        for technique_id in ids:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", technique_id):
                raise ValueError(f"{technique_id!r} is not an ATT&CK technique ID like T1059 or T1059.001")
        return ids


def load_rules(path: Path) -> list[Rule]:
    """Load and validate every rule in a YAML file. Raises RuleError on any problem."""
    try:
        raw = yaml.safe_load(Path(path).read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise RuleError(f"Could not read rules file {path}: {exc}") from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
        raise RuleError(f"Rules file {path} must have a top-level 'rules:' list")

    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for index, raw_rule in enumerate(raw["rules"]):
        label = _rule_label(raw_rule, index)
        try:
            rule = Rule.model_validate(raw_rule)
        except ValidationError as exc:
            raise RuleError(f"Invalid rule {label} in {path}:\n{_format_errors(exc)}") from exc

        if rule.id in seen_ids:
            raise RuleError(f"Duplicate rule id {label} in {path}")
        seen_ids.add(rule.id)
        rules.append(rule)

    return rules


def _rule_label(raw_rule: object, index: int) -> str:
    """'certutil_download' if the rule has an id, otherwise '#3 (no id)'."""
    if isinstance(raw_rule, dict) and raw_rule.get("id"):
        return f"'{raw_rule['id']}'"
    return f"#{index + 1} (no id)"


def _format_errors(exc: ValidationError) -> str:
    """One line per problem, e.g. '  - match.all_of.0.regex: invalid regex ...'."""
    lines = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "(rule)"
        lines.append(f"  - {location}: {error['msg']}")
    return "\n".join(lines)


def _snippet(text: str, found: re.Match) -> tuple[str, tuple[int, int]]:
    """The matched text plus a little context on each side, kept short.

    Also returns where the match sits inside the snippet, so a UI can
    highlight exactly the text the rule matched.
    """
    start = max(0, found.start() - EVIDENCE_CONTEXT_CHARS)
    end = min(len(text), found.end() + EVIDENCE_CONTEXT_CHARS)
    snippet = text[start:end]
    if len(snippet) > MAX_EVIDENCE_CHARS:
        snippet = snippet[:MAX_EVIDENCE_CHARS]
        end = start + MAX_EVIDENCE_CHARS
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    highlight_start = len(prefix) + found.start() - start
    highlight_end = len(prefix) + min(found.end(), end) - start  # The cap can cut the match.
    return f"{prefix}{snippet}{suffix}", (highlight_start, highlight_end)
