"""Check the behavior rules file. Exits 1 if anything is wrong.

Usage: python scripts/check_rules.py [rules.yaml]

1. The rules load and validate (the same check the program runs at startup:
   YAML syntax, required fields, regexes that compile, unique ids).
2. Every ATT&CK technique ID in them exists in data/attack_techniques.json.

CI runs this on its own, so a bad rule fails the build even if the tests are
skipped. tests/test_rules.py covers the same ground.

This is a developer tool, not part of the triage core, so it prints.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # So `rules` imports when run as a script.

from rules import RuleError, load_rules  # After the sys.path line on purpose.

RULES_PATH = ROOT / "rules" / "behavior_rules.yaml"
ATTACK_PATH = ROOT / "data" / "attack_techniques.json"


def problems(rules_path: Path = RULES_PATH, attack_path: Path = ATTACK_PATH) -> list[str]:
    """Everything wrong with the rules file, or an empty list."""
    try:
        rules = load_rules(rules_path)
    except RuleError as exc:
        return [str(exc)]

    known = json.loads(attack_path.read_text())["techniques"]
    return [
        f"Rule '{rule.id}': technique {technique_id} is not in {attack_path.name}"
        for rule in rules
        for technique_id in rule.techniques
        if technique_id not in known
    ]


def main() -> int:
    rules_path = Path(sys.argv[1]) if len(sys.argv) > 1 else RULES_PATH
    found = problems(rules_path)
    for problem in found:
        print(problem, file=sys.stderr)
    if found:
        return 1
    print(f"OK: {rules_path.name} loads and every technique ID is in {ATTACK_PATH.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
