"""
Main entry point for the Vulnerability Triage Engine (Member 3).
Reads findings.json and events.jsonl, computes normalised risk scores and rankings,
generates virtual-patch recommendations, and exports triage_results.json.
"""

import argparse
import json
from pathlib import Path
from typing import Any

from triage.correlator import correlate_finding_events
from triage.loader import load_events, load_findings
from triage.patch_advisor import suggest_virtual_patch
from triage.scorer import calculate_risk_score, classify_priority

DEFAULT_FINDINGS_PATH = Path("findings.json")
DEFAULT_EVENTS_PATH = Path("events.jsonl")
DEFAULT_OUTPUT_PATH = Path("triage_results.json")


def run_triage(
    findings_path: str | Path = DEFAULT_FINDINGS_PATH,
    events_path: str | Path = DEFAULT_EVENTS_PATH,
    output_path: str | Path = DEFAULT_OUTPUT_PATH,
) -> list[dict[str, Any]]:
    findings = load_findings(findings_path)
    events = load_events(events_path)

    results: list[dict[str, Any]] = []

    for finding in findings:
        counts = correlate_finding_events(finding, events)
        observed_count = counts["observed_attack_count"]
        blocked_count = counts["blocked_attack_count"]

        risk_score = calculate_risk_score(finding, observed_count)
        priority = classify_priority(risk_score)
        virtual_patch = suggest_virtual_patch(finding, observed_count)

        results.append(
            {
                "finding_id": finding["id"],
                "title": finding["title"],
                "endpoint": finding["endpoint"],
                "attack_type": str(finding["type"]).strip().lower(),
                "cvss": round(float(finding["cvss"]), 2),
                "asset_criticality": str(finding["asset_criticality"]).strip().lower(),
                "observed_attack_count": observed_count,
                "blocked_attack_count": blocked_count,
                "risk_score": risk_score,
                "priority": priority,
                "suggested_virtual_patch": virtual_patch,
            }
        )

    results.sort(key=lambda r: (-r["risk_score"], -r["cvss"], r["finding_id"]))

    out_path = Path(output_path)
    with out_path.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the Hybrid AI-WAF Vulnerability Triage Engine."
    )
    parser.add_argument("--findings", type=Path, default=DEFAULT_FINDINGS_PATH)
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    args = parser.parse_args()

    ranked = run_triage(
        findings_path=args.findings,
        events_path=args.events,
        output_path=args.output,
    )
    print(f"[Triage Engine] Processed {len(ranked)} findings -> saved to {args.output}")
    for idx, item in enumerate(ranked, start=1):
        print(
            f"  #{idx} [{item['priority']}] {item['title']} ({item['endpoint']}) | "
            f"Risk: {item['risk_score']}/10 | Attacks: {item['observed_attack_count']}"
        )


if __name__ == "__main__":
    main()
