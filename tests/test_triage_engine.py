"""Independent unit and edge-case tests for Member 3's Vulnerability Triage Engine."""

import json
from pathlib import Path

from triage.correlator import correlate_finding_events, endpoints_match, normalize_endpoint
from triage.loader import load_events
from triage.scorer import calculate_risk_score, classify_priority
from triage_engine import run_triage


def test_endpoint_normalization_and_matching():
    assert normalize_endpoint("/vulnerabilities/sqli/?id=1") == "/vulnerabilities/sqli"
    assert endpoints_match("/vulnerabilities/sqli/", "/vulnerabilities/sqli") is True
    assert endpoints_match("/vulnerabilities/sqli/", "/vulnerabilities/sqli/test") is True
    assert endpoints_match("/vulnerabilities/sqli/", "/vulnerabilities/xss_r/") is False
    assert endpoints_match("*", "/any/path") is True


def test_zero_attack_events_still_produces_meaningful_score():
    finding = {
        "id": 10,
        "title": "Unattacked SQLi",
        "endpoint": "/vulnerabilities/sqli/",
        "type": "sqli",
        "cvss": 9.8,
        "asset_criticality": "high",
    }
    score = calculate_risk_score(finding, observed_attack_count=0)
    assert score == 7.52
    assert classify_priority(score) == "HIGH"


def test_active_attacks_increase_risk_score():
    finding = {
        "id": 10,
        "title": "Attacked SQLi",
        "endpoint": "/vulnerabilities/sqli/",
        "type": "sqli",
        "cvss": 9.8,
        "asset_criticality": "high",
    }
    zero_score = calculate_risk_score(finding, observed_attack_count=0)
    active_score = calculate_risk_score(finding, observed_attack_count=25)
    assert active_score > zero_score
    assert active_score <= 10.0


def test_correlator_ignores_benign_and_wrong_type_events():
    finding = {
        "id": 1,
        "title": "SQLi",
        "endpoint": "/vulnerabilities/sqli/",
        "type": "sqli",
        "cvss": 9.0,
        "asset_criticality": "high",
    }
    events = [
        {"path": "/vulnerabilities/sqli/", "attack_type": "sqli", "verdict": "block"},
        {"path": "/vulnerabilities/sqli/", "attack_type": "sqli", "verdict": "allow"},
        {"path": "/vulnerabilities/sqli/", "attack_type": "none", "verdict": "allow"},
        {"path": "/vulnerabilities/sqli/", "attack_type": "xss", "verdict": "block"},
        {"path": "/other/", "attack_type": "sqli", "verdict": "block"},
    ]
    counts = correlate_finding_events(finding, events)
    assert counts["observed_attack_count"] == 2
    assert counts["blocked_attack_count"] == 1


def test_loader_handles_missing_and_corrupt_events(tmp_path: Path):
    missing = tmp_path / "nonexistent.jsonl"
    assert load_events(missing) == []

    corrupt_file = tmp_path / "events.jsonl"
    corrupt_file.write_text(
        '{"attack_type": "sqli", "path": "/a", "verdict": "block"}\n'
        'NOT_VALID_JSON\n'
        '\n'
        '{"attack_type": "xss", "path": "/b", "verdict": "block"}\n',
        encoding="utf-8",
    )
    loaded = load_events(corrupt_file)
    assert len(loaded) == 2


def test_end_to_end_triage_schema_and_sorting(tmp_path: Path):
    findings_file = tmp_path / "findings.json"
    events_file = tmp_path / "events.jsonl"
    out_file = tmp_path / "triage_results.json"

    findings_file.write_text(
        json.dumps(
            [
                {
                    "id": 1,
                    "title": "Low XSS",
                    "endpoint": "/xss",
                    "type": "xss",
                    "cvss": 4.3,
                    "asset_criticality": "low",
                },
                {
                    "id": 2,
                    "title": "Critical SQLi",
                    "endpoint": "/sqli",
                    "type": "sqli",
                    "cvss": 9.8,
                    "asset_criticality": "critical",
                },
            ]
        ),
        encoding="utf-8",
    )
    events_file.write_text(
        '{"ts":"2026-11-17T10:00:00","ip":"127.0.0.1","method":"GET","path":"/sqli","payload":"1 OR 1=1","verdict":"block","attack_type":"sqli","score":0.99}\n',
        encoding="utf-8",
    )

    results = run_triage(findings_file, events_file, out_file)
    assert out_file.exists()
    assert len(results) == 2
    assert results[0]["finding_id"] == 2
    assert results[0]["risk_score"] > results[1]["risk_score"]

    expected_keys = {
        "finding_id",
        "title",
        "endpoint",
        "attack_type",
        "cvss",
        "asset_criticality",
        "observed_attack_count",
        "blocked_attack_count",
        "risk_score",
        "priority",
        "suggested_virtual_patch",
    }
    assert set(results[0].keys()) == expected_keys
