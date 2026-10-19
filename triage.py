"""Triage logic: enrich an alert's indicators and decide on a verdict."""

from enrichers.virustotal import lookup_sha256
from models import Alert, EnrichmentResult, TriageResult, Verdict

# A hash flagged by this many engines or more is considered malicious.
# Anything from 1 up to this number is suspicious.
MALICIOUS_THRESHOLD = 5


def triage(alert: Alert) -> TriageResult:
    """Enrich the alert and return a structured triage result."""
    enrichments: list[EnrichmentResult] = []

    if alert.sha256:
        enrichments.append(lookup_sha256(alert.sha256))

    if not enrichments:
        return TriageResult(
            alert=alert,
            enrichments=[],
            verdict="unknown",
            reasons=["Alert has no SHA256, so there was nothing to enrich"],
        )

    # Milestone 1 has only one enrichment, so its verdict is the final verdict.
    # When more enrichers are added, this is where their verdicts get combined.
    verdict, reason = verdict_for_hash(enrichments[0])

    return TriageResult(
        alert=alert,
        enrichments=enrichments,
        verdict=verdict,
        reasons=[reason],
    )


def verdict_for_hash(result: EnrichmentResult) -> tuple[Verdict, str]:
    """Decide a verdict for one hash lookup and explain why."""
    if result.error:
        return "unknown", f"{result.source}: {result.error}"

    detections = f"{result.malicious_count}/{result.total_engines} engines"

    if result.malicious_count >= MALICIOUS_THRESHOLD:
        return "malicious", (
            f"{result.source}: {detections} flagged the file as malicious "
            f"(threshold is {MALICIOUS_THRESHOLD})"
        )
    if result.malicious_count >= 1:
        return "suspicious", (
            f"{result.source}: {detections} flagged the file as malicious "
            f"(below the malicious threshold of {MALICIOUS_THRESHOLD})"
        )
    return "clean", f"{result.source}: no engines flagged the file ({detections})"
