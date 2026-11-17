"""
data_access.py - the ONLY place that touches files or the backend.

The dashboard never reads files itself; it calls the functions below.
Everything here is tolerant: missing files / bad lines never crash the UI.

Data folder lookup order:
  1. env var WAF_DATA_DIR
  2. ./data   (if it contains events.jsonl or events.json)
  3. ./samples (bundled preview data -> flagged as sample)
"""
from __future__ import annotations

import importlib
import json
import os
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
EVENT_COLUMNS = ["timestamp", "source_ip", "method", "endpoint",
                 "attack_type", "verdict", "score"]
TRIAGE_COLUMNS = ["vuln_id", "title", "endpoint", "attack_type", "cvss",
                  "asset_criticality", "observed_attacks", "risk_score",
                  "priority", "virtual_patch"]

# Accepted field-name variants (so small naming differences don't break us).
EVENT_ALIASES = {
    "timestamp": ["timestamp", "time", "ts", "@timestamp"],
    "source_ip": ["source_ip", "src_ip", "ip", "client_ip"],
    "method": ["method", "http_method"],
    "endpoint": ["endpoint", "path", "url", "uri"],
    "attack_type": ["attack_type", "attack", "category", "label"],
    "verdict": ["verdict", "action", "decision"],
    "score": ["score", "detection_score", "confidence", "probability"],
}
TRIAGE_ALIASES = {
    "vuln_id": ["vuln_id", "id", "vulnerability_id"],
    "title": ["title", "name", "vulnerability"],
    "endpoint": ["endpoint", "path", "url"],
    "attack_type": ["attack_type", "attack", "category"],
    "cvss": ["cvss", "cvss_score"],
    "asset_criticality": ["asset_criticality", "criticality"],
    "observed_attacks": ["observed_attacks", "attack_count", "observed"],
    "risk_score": ["risk_score", "risk"],
    "priority": ["priority", "severity"],
    "virtual_patch": ["virtual_patch", "suggested_patch", "patch"],
}
ATTACK_MAP = {
    "sqli": "SQL Injection", "sql_injection": "SQL Injection",
    "xss": "XSS", "cross_site_scripting": "XSS",
    "path_traversal": "Path Traversal", "directory_traversal": "Path Traversal",
    "lfi": "Path Traversal",
}
NO_ATTACK = {"", "none", "benign", "normal", "clean", "null", "nan"}


# ------------------------------------------------------------------ locating
def data_source() -> tuple[Path, bool]:
    """Return (folder, is_sample)."""
    env = os.getenv("WAF_DATA_DIR")
    if env:
        return Path(env), False
    data = BASE_DIR / "data"
    if (data / "events.jsonl").exists() or (data / "events.json").exists():
        return data, False
    return BASE_DIR / "samples", True


def _read_records(path: Path) -> tuple[list[dict], dict]:
    """Read .jsonl (one JSON per line) or .json (list / {key: list})."""
    meta = {"path": str(path), "error": None, "skipped": 0}
    if not path.exists():
        meta["error"] = f"File not found: {path.name}"
        return [], meta
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        meta["error"] = f"Cannot read {path.name}: {exc}"
        return [], meta
    if not text:
        return [], meta
    records: list = []
    try:
        if path.suffix == ".jsonl":
            raise ValueError  # go to line-by-line parsing
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("events", "results", "data", "items", "vulnerabilities"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
            else:
                data = [data]
        records = data
    except ValueError:
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                meta["skipped"] += 1
    return [r for r in records if isinstance(r, dict)], meta


def _apply_aliases(df: pd.DataFrame, aliases: dict, columns: list) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    for col in columns:
        src = next((a for a in aliases[col] if a in df.columns), None)
        out[col] = df[src] if src else pd.NA
    return out


def normalize_attack(value) -> str:
    s = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if s in NO_ATTACK or value is None or value is pd.NA:
        return "None"
    return ATTACK_MAP.get(s, str(value).strip())


def normalize_verdict(value) -> str:
    s = str(value).strip().upper()
    if s in ("BLOCK", "BLOCKED", "DENY", "DENIED"):
        return "BLOCK"
    if s in ("ALLOW", "ALLOWED", "PASS", "PERMIT"):
        return "ALLOW"
    return s if s not in ("", "NAN", "<NA>") else "UNKNOWN"


# ------------------------------------------------------------------- loaders
def load_events() -> tuple[pd.DataFrame, dict]:
    """Security events, newest first. Never invents data."""
    folder, is_sample = data_source()
    path = folder / "events.jsonl"
    if not path.exists():
        path = folder / "events.json"
    records, meta = _read_records(path)
    meta["is_sample"] = is_sample
    if not records:
        return pd.DataFrame(columns=EVENT_COLUMNS), meta
    df = _apply_aliases(pd.DataFrame(records), EVENT_ALIASES, EVENT_COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True).dt.tz_localize(None)
    df["attack_type"] = df["attack_type"].map(normalize_attack)
    df["verdict"] = df["verdict"].map(normalize_verdict)
    df["method"] = df["method"].astype(str).str.upper().replace("<NA>", "—")
    df["score"] = pd.to_numeric(df["score"], errors="coerce")
    df = df.sort_values("timestamp", ascending=False, na_position="last").reset_index(drop=True)
    return df, meta


def load_triage() -> tuple[pd.DataFrame, dict]:
    folder, is_sample = data_source()
    records, meta = _read_records(folder / "triage_results.json")
    meta["is_sample"] = is_sample
    if not records:
        return pd.DataFrame(columns=TRIAGE_COLUMNS), meta
    df = _apply_aliases(pd.DataFrame(records), TRIAGE_ALIASES, TRIAGE_COLUMNS)
    for col in ("cvss", "observed_attacks", "risk_score"):
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df["attack_type"] = df["attack_type"].map(normalize_attack)
    df["priority"] = df["priority"].astype(str).str.upper().replace({"<NA>": "—", "NAN": "—"})
    return df, meta


def load_status() -> tuple[dict, dict]:
    folder, is_sample = data_source()
    path = folder / "system_status.json"
    meta = {"path": str(path), "error": None, "is_sample": is_sample}
    if not path.exists():
        meta["error"] = "system_status.json not found"
        return {}, meta
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return (data if isinstance(data, dict) else {}), meta
    except (OSError, ValueError) as exc:
        meta["error"] = f"Cannot parse system_status.json: {exc}"
        return {}, meta


# ------------------------------------------------------------------- metrics
def compute_metrics(df: pd.DataFrame) -> dict:
    """All numbers come from the event log. Rate is None when no data."""
    total = len(df)
    allowed = int((df["verdict"] == "ALLOW").sum())
    blocked = int((df["verdict"] == "BLOCK").sum())
    attacks = int((df["attack_type"] != "None").sum())
    return {
        "total": total, "allowed": allowed, "blocked": blocked, "attacks": attacks,
        "detection_rate": (attacks / total * 100) if total else None,
        "block_rate": (blocked / total * 100) if total else None,
    }


# ------------------------------------------------------------------- retrain
def retrain_entrypoint() -> str:
    return os.getenv("WAF_RETRAIN_ENTRYPOINT", "model_service:retrain")


def run_retrain() -> dict:
    """
    Call the REAL backend retraining function ("module:function").
    Nothing is simulated: if the backend is not installed we say so.
    """
    target = retrain_entrypoint()
    try:
        module_name, func_name = target.split(":")
        func = getattr(importlib.import_module(module_name), func_name)
    except (ValueError, ImportError, AttributeError) as exc:
        return {"ok": False, "message":
                f"Backend retraining interface '{target}' is not available ({exc}). "
                "Agree the entrypoint with the ML owner - see BACKEND_INTEGRATION.md."}
    try:
        result = func()
    except Exception as exc:  # backend errors must be shown, not hidden
        return {"ok": False, "message": f"Retraining failed: {exc}"}
    return {"ok": True, "message": "Retraining finished.", "result": result}
