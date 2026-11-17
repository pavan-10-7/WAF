"""Advisory virtual-patch rule generator."""

from typing import Any

from triage.config import DEFAULT_VIRTUAL_PATCH, VIRTUAL_PATCH_TEMPLATES


def suggest_virtual_patch(finding: dict[str, Any], observed_attack_count: int) -> str:
    attack_type = str(finding.get("type", "")).strip().lower()
    endpoint = str(finding.get("endpoint", "/"))

    template = VIRTUAL_PATCH_TEMPLATES.get(attack_type, DEFAULT_VIRTUAL_PATCH)
    recommendation = template.format(endpoint=endpoint, attack_type=attack_type)

    if observed_attack_count > 0:
        recommendation += (
            f" [Active Threat: {observed_attack_count} matching attack event(s) observed in WAF logs.]"
        )
    else:
        recommendation += " [Proactive Hardening: 0 active attacks observed so far.]"

    return recommendation
