"""Normalised vulnerability risk scoring and prioritisation logic."""

import math
from typing import Any

from triage.config import (
    CRITICALITY_MAP,
    DEFAULT_CRITICALITY,
    DEFAULT_EXPLOITABILITY,
    EXPLOITABILITY_BY_TYPE,
    FREQUENCY_SATURATION_CAP,
    PRIORITY_THRESHOLDS,
    WEIGHT_CRITICALITY,
    WEIGHT_CVSS,
    WEIGHT_EXPLOITABILITY,
    WEIGHT_FREQUENCY,
)


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def normalize_cvss(cvss: float | int) -> float:
    return _clamp(float(cvss) / 10.0)


def normalize_exploitability(finding: dict[str, Any]) -> float:
    raw_exp = finding.get("exploitability")
    if raw_exp is not None:
        val = float(raw_exp)
        return _clamp(val / 10.0 if val > 1.0 else val)

    attack_type = str(finding.get("type", "")).strip().lower()
    return EXPLOITABILITY_BY_TYPE.get(attack_type, DEFAULT_EXPLOITABILITY)


def normalize_criticality(asset_criticality: str) -> float:
    key = str(asset_criticality).strip().lower()
    return CRITICALITY_MAP.get(key, DEFAULT_CRITICALITY)


def normalize_attack_frequency(observed_count: int) -> float:
    count = max(0, int(observed_count))
    if count == 0:
        return 0.0
    numerator = math.log1p(count)
    denominator = math.log1p(FREQUENCY_SATURATION_CAP)
    return _clamp(numerator / denominator)


def calculate_risk_score(finding: dict[str, Any], observed_attack_count: int) -> float:
    c_norm = normalize_cvss(finding["cvss"])
    e_norm = normalize_exploitability(finding)
    a_norm = normalize_criticality(finding["asset_criticality"])
    f_norm = normalize_attack_frequency(observed_attack_count)

    weighted_sum = (
        WEIGHT_CVSS * c_norm
        + WEIGHT_EXPLOITABILITY * e_norm
        + WEIGHT_CRITICALITY * a_norm
        + WEIGHT_FREQUENCY * f_norm
    )
    return round(10.0 * _clamp(weighted_sum), 2)


def classify_priority(risk_score: float) -> str:
    for threshold, label in PRIORITY_THRESHOLDS:
        if risk_score >= threshold:
            return label
    return "LOW"
