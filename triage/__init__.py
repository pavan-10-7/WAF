"""Member 3 Vulnerability Triage Engine package."""

from triage.correlator import correlate_finding_events
from triage.loader import load_events, load_findings
from triage.patch_advisor import suggest_virtual_patch
from triage.scorer import calculate_risk_score, classify_priority

__all__ = [
    "correlate_finding_events",
    "load_events",
    "load_findings",
    "suggest_virtual_patch",
    "calculate_risk_score",
    "classify_priority",
]
