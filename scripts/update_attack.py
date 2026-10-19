"""Download MITRE ATT&CK (Enterprise) and write a compact technique lookup.

Usage: python scripts/update_attack.py

Writes data/attack_techniques.json, which maps each technique ID to its name
and tactics. Commit that file so the tool works offline. Re-run this script
when MITRE publishes a new ATT&CK release.

This is a developer tool, not part of the triage core, so it prints a
one-line summary when it finishes.
"""

import json
from datetime import date
from pathlib import Path

import httpx

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data" / "attack_techniques.json"


def main() -> None:
    response = httpx.get(STIX_URL, timeout=120.0, follow_redirects=True)
    response.raise_for_status()
    bundle = response.json()

    compact = build_lookup(bundle["objects"])
    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(compact, indent=2, sort_keys=False) + "\n")

    print(
        f"Wrote {len(compact['techniques'])} techniques "
        f"(ATT&CK v{compact['attack_version']}) to {OUTPUT_PATH}"
    )


def build_lookup(objects: list[dict]) -> dict:
    """Turn the STIX objects into {"techniques": {id: {name, tactics}}, ...}."""
    active = [o for o in objects if not o.get("revoked") and not o.get("x_mitre_deprecated")]

    # Tactics: STIX refers to them by "shortname" (e.g. "defense-evasion").
    tactic_names = {
        o["x_mitre_shortname"]: o["name"] for o in active if o["type"] == "x-mitre-tactic"
    }
    tactic_ids = {o["id"]: o["name"] for o in active if o["type"] == "x-mitre-tactic"}

    # The matrix lists tactics in kill-chain order (Reconnaissance → Impact).
    matrix = next(o for o in active if o["type"] == "x-mitre-matrix")
    tactic_order = [tactic_ids[ref] for ref in matrix["tactic_refs"] if ref in tactic_ids]

    collection = next((o for o in objects if o["type"] == "x-mitre-collection"), {})

    # First pass: plain names, so sub-techniques can include their parent's name.
    names: dict[str, str] = {}
    tactics: dict[str, list[str]] = {}
    for obj in active:
        if obj["type"] != "attack-pattern":
            continue
        technique_id = _attack_id(obj)
        if technique_id is None:
            continue
        names[technique_id] = obj["name"]
        tactics[technique_id] = [
            tactic_names[phase["phase_name"]]
            for phase in obj.get("kill_chain_phases", [])
            if phase["kill_chain_name"] == "mitre-attack" and phase["phase_name"] in tactic_names
        ]

    techniques = {}
    for technique_id in sorted(names):
        name = names[technique_id]
        if "." in technique_id:
            # "PowerShell" → "Command and Scripting Interpreter: PowerShell"
            parent_name = names.get(technique_id.split(".")[0])
            if parent_name:
                name = f"{parent_name}: {name}"
        techniques[technique_id] = {"name": name, "tactics": tactics[technique_id]}

    return {
        "source": STIX_URL,
        "attack_version": collection.get("x_mitre_version", "unknown"),
        "generated": date.today().isoformat(),
        "tactic_order": tactic_order,
        "techniques": techniques,
    }


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


if __name__ == "__main__":
    main()
