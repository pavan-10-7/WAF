"""Correlates WAF security events (events.jsonl) with vulnerability findings (findings.json)."""

from typing import Any


def normalize_endpoint(endpoint: str) -> str:
    if not endpoint:
        return "/"
    base = endpoint.split("?", 1)[0].strip().lower()
    if base != "/" and base.endswith("/"):
        base = base.rstrip("/")
    return base or "/"


def endpoints_match(finding_endpoint: str, event_path: str) -> bool:
    if finding_endpoint.strip() == "*":
        return True

    norm_finding = normalize_endpoint(finding_endpoint)
    norm_event = normalize_endpoint(event_path)

    if norm_finding == norm_event:
        return True

    if norm_finding != "/" and norm_event.startswith(norm_finding + "/"):
        return True

    return False


def correlate_finding_events(
    finding: dict[str, Any], events: list[dict[str, Any]]
) -> dict[str, int]:
    target_type = str(finding.get("type", "")).strip().lower()
    target_endpoint = str(finding.get("endpoint", "/"))

    observed_count = 0
    blocked_count = 0

    for event in events:
        event_type = str(event.get("attack_type", "none")).strip().lower()
        if event_type == "none" or event_type != target_type:
            continue

        event_path = str(event.get("path", "/"))
        if not endpoints_match(target_endpoint, event_path):
            continue

        observed_count += 1
        if str(event.get("verdict", "")).strip().lower() == "block":
            blocked_count += 1

    return {
        "observed_attack_count": observed_count,
        "blocked_attack_count": blocked_count,
    }
