"""Triage logic: enrich indicators, analyze behavior, and decide on a verdict."""

from collections.abc import Callable
from typing import NamedTuple

import attack
import behavior
from cache import Cache
from enrichers import abuseipdb, virustotal
from models import (
    VERDICT_RANK,
    Alert,
    BehaviorFinding,
    EnrichmentResult,
    IndicatorType,
    TriageResult,
    Verdict,
)

# VirusTotal: this many engines or more → malicious; 1 up to this → suspicious.
VT_MALICIOUS_THRESHOLD = 5

# AbuseIPDB abuse confidence score (0-100).
ABUSEIPDB_MALICIOUS_SCORE = 75  # score >= 75 → malicious
ABUSEIPDB_SUSPICIOUS_SCORE = 25  # 25-74 → suspicious, below 25 → clean

# Behavior severity → verdict mapping and the escalation rule live at the
# top of behavior.py. Verdict ranking (VERDICT_RANK) lives in models.py.


class Enricher(NamedTuple):
    alert_field: str  # Which Alert field supplies the indicator.
    source: str
    indicator_type: IndicatorType
    lookup: Callable[[str], EnrichmentResult]


# Every enricher, in the order it runs. To add a new source, add a line here
# and a verdict rule in verdict_for().
ENRICHERS = [
    Enricher("sha256", virustotal.SOURCE, "sha256", virustotal.lookup_sha256),
    Enricher("remote_ip", virustotal.SOURCE, "ip", virustotal.lookup_ip),
    Enricher("remote_ip", abuseipdb.SOURCE, "ip", abuseipdb.lookup_ip),
    Enricher("domain", virustotal.SOURCE, "domain", virustotal.lookup_domain),
]


def triage(alert: Alert, cache: Cache | None = None) -> TriageResult:
    """Enrich indicators, analyze behavior, and combine everything into one verdict."""
    if cache is None:
        cache = Cache()

    enrichments: list[EnrichmentResult] = []
    reasons: list[str] = []

    for enricher in ENRICHERS:
        value = getattr(alert, enricher.alert_field)
        if not value:
            continue

        result = cache.get_or_lookup(
            enricher.source, enricher.indicator_type, value, enricher.lookup
        )
        verdict, finding = verdict_for(result)
        enrichments.append(result.model_copy(update={"verdict": verdict}))

        # Two sources skipping the same IP would give the same reason twice.
        reason = f"{enricher.alert_field} {value} {finding}"
        if reason not in reasons:
            reasons.append(reason)

    # Behavior analysis only counts toward the verdict if there was process
    # data to analyze. "Ran and found nothing" is a clean result; "had nothing
    # to look at" is no result at all.
    findings: list[BehaviorFinding] = []
    behavior_result: Verdict | None = None
    if behavior.has_behavior_data(alert):
        findings = behavior.analyze(alert)
        behavior_result = behavior.behavior_verdict(findings)
        reasons.extend(behavior_reasons(findings))

    if not enrichments and behavior_result is None:
        return TriageResult(
            alert=alert,
            enrichments=[],
            verdict="unknown",
            reasons=["Alert has no indicators or process details, so there was nothing to analyze"],
        )

    tactics = attack.order_tactics(
        tactic for f in findings for t in f.techniques for tactic in t.tactics
    )

    return TriageResult(
        alert=alert,
        enrichments=enrichments,
        verdict=overall_verdict(enrichments, behavior_result),
        reasons=reasons,
        behavior_findings=findings,
        decoded_command=behavior.decode_encoded_command(alert.command_line),
        tactics=tactics,
    )


def overall_verdict(
    enrichments: list[EnrichmentResult], behavior_result: Verdict | None = None
) -> Verdict:
    """Combine individual verdicts: the worst one wins.

    Intel and behavior are treated the same way: a malicious finding from
    either side makes the alert malicious.

    Skipped lookups (private IPs, reserved domains) are left out, because
    there was nothing to check, not a failed check. If nothing is left,
    the alert is unknown.
    """
    verdicts = [e.verdict for e in enrichments if e.skip_reason is None]
    if behavior_result is not None:
        verdicts.append(behavior_result)
    if not verdicts:
        return "unknown"
    return max(verdicts, key=lambda verdict: VERDICT_RANK[verdict])


def behavior_reasons(findings: list[BehaviorFinding]) -> list[str]:
    """One reason per behavior finding, plus a note if escalation kicked in."""
    if not findings:
        return ["behavior: no behavior rules matched"]

    reasons = []
    for f in findings:
        technique_ids = ", ".join(t.id for t in f.techniques)
        where = "decoded PowerShell command" if f.from_decoded else f.matched_field
        effect = ", context only" if behavior.SEVERITY_VERDICT[f.severity] is None else ""
        reasons.append(
            f"behavior: {f.rule_name} [{technique_ids}] ({f.severity}{effect}) "
            f"in {where}: {f.evidence}"
        )

    if behavior.escalation_applies(findings):
        reasons.append(
            f"behavior: {behavior.ESCALATION_MEDIUM_COUNT}+ different medium-severity "
            f"findings on one alert escalate it to malicious"
        )
    return reasons


def verdict_for(result: EnrichmentResult) -> tuple[Verdict, str]:
    """Decide a verdict for one enrichment and describe the finding."""
    if result.skip_reason:
        return "unknown", f"skipped: {result.skip_reason}"
    if result.error:
        return "unknown", f"could not be checked ({result.source}): {result.error}"

    if result.source == virustotal.SOURCE:
        return _virustotal_verdict(result)
    if result.source == abuseipdb.SOURCE:
        return _abuseipdb_verdict(result)
    return "unknown", f"has no verdict rule for source {result.source}"


def _virustotal_verdict(result: EnrichmentResult) -> tuple[Verdict, str]:
    detections = f"{result.malicious_count}/{result.total_engines} VT engines"

    if result.malicious_count >= VT_MALICIOUS_THRESHOLD:
        return "malicious", (
            f"flagged by {detections} (malicious threshold is {VT_MALICIOUS_THRESHOLD})"
        )
    if result.malicious_count >= 1:
        return "suspicious", (
            f"flagged by {detections} (below the malicious threshold of {VT_MALICIOUS_THRESHOLD})"
        )
    return "clean", f"flagged by 0/{result.total_engines} VT engines"


def _abuseipdb_verdict(result: EnrichmentResult) -> tuple[Verdict, str]:
    finding = (
        f"has AbuseIPDB abuse confidence {result.score}/100 "
        f"from {result.report_count} reports in the last {abuseipdb.MAX_AGE_IN_DAYS} days"
    )

    if result.score >= ABUSEIPDB_MALICIOUS_SCORE:
        return "malicious", f"{finding} (malicious at {ABUSEIPDB_MALICIOUS_SCORE}+)"
    if result.score >= ABUSEIPDB_SUSPICIOUS_SCORE:
        return "suspicious", f"{finding} (suspicious at {ABUSEIPDB_SUSPICIOUS_SCORE}+)"
    return "clean", finding
