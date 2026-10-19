"""Triage logic: enrich an alert's indicators and decide on a verdict."""

from collections.abc import Callable
from typing import NamedTuple

from cache import Cache
from enrichers import abuseipdb, virustotal
from models import Alert, EnrichmentResult, IndicatorType, TriageResult, Verdict

# VirusTotal: this many engines or more → malicious; 1 up to this → suspicious.
VT_MALICIOUS_THRESHOLD = 5

# AbuseIPDB abuse confidence score (0-100).
ABUSEIPDB_MALICIOUS_SCORE = 75  # score >= 75 → malicious
ABUSEIPDB_SUSPICIOUS_SCORE = 25  # 25-74 → suspicious, below 25 → clean

# Higher number = worse. The overall verdict is the worst individual verdict.
# "unknown" outranks "clean": if we couldn't check something, we can't call
# the whole alert clean.
SEVERITY: dict[Verdict, int] = {"clean": 0, "unknown": 1, "suspicious": 2, "malicious": 3}


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
    """Enrich every indicator in the alert and combine the results into one verdict."""
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

    if not enrichments:
        return TriageResult(
            alert=alert,
            enrichments=[],
            verdict="unknown",
            reasons=["Alert has no sha256, remote_ip, or domain, so there was nothing to enrich"],
        )

    return TriageResult(
        alert=alert,
        enrichments=enrichments,
        verdict=overall_verdict(enrichments),
        reasons=reasons,
    )


def overall_verdict(enrichments: list[EnrichmentResult]) -> Verdict:
    """Combine individual verdicts: the worst one wins.

    Skipped lookups (private IPs, reserved domains) are left out, because
    there was nothing to check, not a failed check. If every lookup was
    skipped, the alert is unknown.
    """
    verdicts = [e.verdict for e in enrichments if e.skip_reason is None]
    if not verdicts:
        return "unknown"
    return max(verdicts, key=lambda verdict: SEVERITY[verdict])


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
