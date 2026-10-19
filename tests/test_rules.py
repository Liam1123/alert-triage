"""Tests for loading and validating the rules file, and the ATT&CK data."""

import json
import textwrap

import pytest

import attack
import behavior
from rules import RuleError, load_rules

VALID_RULE = """
  - id: test_rule
    name: Test rule
    description: For tests.
    techniques: [T1059.001]
    severity: medium
    match:
      all_of:
        - field: command_line
          regex: 'foo'
"""


def write_rules(tmp_path, body: str):
    path = tmp_path / "rules.yaml"
    path.write_text("rules:\n" + textwrap.dedent(body))
    return path


def test_real_rules_file_loads():
    assert len(behavior.RULES) >= 12


def test_every_technique_in_rules_exists_in_attack_data():
    data = json.loads(attack.DATA_PATH.read_text())
    for rule in behavior.RULES:
        for technique_id in rule.techniques:
            assert technique_id in data["techniques"], f"{rule.id}: unknown technique {technique_id}"


def test_technique_lookup():
    t = attack.technique("T1059.001")
    assert t.name == "Command and Scripting Interpreter: PowerShell"
    assert t.tactics == ["Execution"]
    assert attack.technique("T9999").name.startswith("Unknown technique")


def test_tactics_are_ordered_by_kill_chain():
    assert attack.order_tactics(["Impact", "Execution", "Impact", "Initial Access"]) == [
        "Initial Access", "Execution", "Impact",
    ]


def test_valid_rule_loads(tmp_path):
    rules = load_rules(write_rules(tmp_path, VALID_RULE))
    assert rules[0].id == "test_rule"


@pytest.mark.parametrize("broken_line, replacement, expected_message", [
    ("severity: medium", "severity: critical", "severity"),
    ("regex: 'foo'", "regex: 'foo('", "invalid regex"),
    ("field: command_line", "field: comand_line", "field"),
    ("techniques: [T1059.001]", "techniques: [T1059.1]", "not an ATT&CK technique ID"),
    ("techniques: [T1059.001]", "techniques: []", "techniques"),
    ("all_of:", "every_of:", "every_of"),
])
def test_malformed_rule_names_the_rule(tmp_path, broken_line, replacement, expected_message):
    path = write_rules(tmp_path, VALID_RULE.replace(broken_line, replacement))

    with pytest.raises(RuleError) as excinfo:
        load_rules(path)

    message = str(excinfo.value)
    assert "'test_rule'" in message
    assert expected_message in message


def test_missing_required_field(tmp_path):
    body = VALID_RULE.replace("    description: For tests.\n", "")
    with pytest.raises(RuleError, match=r"(?s)'test_rule'.*description"):
        load_rules(write_rules(tmp_path, body))


def test_group_with_both_all_and_any(tmp_path):
    body = VALID_RULE + "      any_of:\n        - field: image\n          regex: 'bar'\n"
    with pytest.raises(RuleError, match="exactly one of 'all_of' or 'any_of'"):
        load_rules(write_rules(tmp_path, body))


def test_duplicate_rule_id(tmp_path):
    with pytest.raises(RuleError, match="Duplicate rule id 'test_rule'"):
        load_rules(write_rules(tmp_path, VALID_RULE + VALID_RULE))


def test_rule_without_id_is_named_by_position(tmp_path):
    body = VALID_RULE.replace("  - id: test_rule\n    name", "  - name")
    with pytest.raises(RuleError, match=r"#1 \(no id\)"):
        load_rules(write_rules(tmp_path, body))


def test_yaml_syntax_error(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("rules:\n  - id: [unclosed\n")
    with pytest.raises(RuleError, match="Could not read rules file"):
        load_rules(path)


def test_missing_rules_list(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("- id: x\n")
    with pytest.raises(RuleError, match="top-level 'rules:' list"):
        load_rules(path)
