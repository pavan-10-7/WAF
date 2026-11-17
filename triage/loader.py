"""Resilient data loaders for vulnerability findings (JSON) and WAF events (JSONL)."""

import json
from pathlib import Path
from typing import Any

REQUIRED_FINDING_KEYS = {"id", "title", "endpoint", "type", "cvss", "asset_criticality"}


def load_findings(findings_path: str | Path) -> list[dict[str, Any]]:
    path = Path(findings_path)
    if not path.exists():
        raise FileNotFoundError(f"Findings file not found: {path}")

    with path.open("r", encoding="utf-8-sig") as handle:
        data = json.load(handle)

    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON list in {path}, got {type(data).__name__}")

    validated: list[dict[str, Any]] = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Finding at index {idx} must be a JSON object.")
        missing = REQUIRED_FINDING_KEYS - set(item.keys())
        if missing:
            raise ValueError(f"Finding at index {idx} is missing required keys: {sorted(missing)}")
        validated.append(item)

    return validated


def load_events(events_path: str | Path) -> list[dict[str, Any]]:
    path = Path(events_path)
    if not path.exists():
        return []

    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
                if isinstance(record, dict):
                    events.append(record)
            except json.JSONDecodeError:
                continue

    return events