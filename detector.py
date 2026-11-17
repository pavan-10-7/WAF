"""Importable hybrid detector: detect(req: dict) -> dict."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib

from rules import detect_rule, normalize

MODEL_PATH = Path(__file__).resolve().parent / "models" / "detector.joblib"
RULE_CONFIDENCE = 0.97
ML_BLOCK_THRESHOLD = 0.82
_model: Any = None
_model_loaded = False



def _request_text(req: dict) -> str:
    """Build detection input from request data, excluding transport metadata.

    HTTP headers contain browser and proxy metadata that can cause false
    positives. Inspect the method, path, query and body instead.
    """
    parts = [
        str(req.get(key, "") or "")
        for key in ("method", "path", "query", "body")
    ]
    return normalize(" ".join(parts))



def _load_model() -> Any:
    global _model, _model_loaded
    if not _model_loaded:
        _model_loaded = True
        if MODEL_PATH.is_file():
            try:
                _model = joblib.load(MODEL_PATH)
            except (OSError, ValueError, EOFError):
                _model = None
    return _model


def detect(req: dict) -> dict:
    """Return the shared contract fields; malformed input safely defaults to allow."""
    if not isinstance(req, dict):
        req = {}
    text = _request_text(req)
    rule_type, rule_reason = detect_rule(text)
    if rule_type:
        return {"verdict": "block", "attack_type": rule_type,
                "score": RULE_CONFIDENCE, "reason": rule_reason}

    model = _load_model()
    if model is not None:
        try:
            probabilities = model.predict_proba([text])[0]
            classes = list(model.classes_)
            best_index = int(probabilities.argmax())
            label = str(classes[best_index])
            score = float(probabilities[best_index])
            # Model-only blocks require strong confidence; rules have precedence.
            if label in {"sqli", "xss", "traversal"} and score >= ML_BLOCK_THRESHOLD:
                names = {"sqli": "SQL injection", "xss": "Cross-site scripting",
                         "traversal": "Path traversal"}
                return {"verdict": "block", "attack_type": label, "score": score,
                        "reason": f"ML classifier identified {names[label]} (confidence {score:.2f})"}
        except (AttributeError, IndexError, TypeError, ValueError):
            pass
    return {"verdict": "allow", "attack_type": "none", "score": 0.0,
            "reason": "No supported attack pattern detected"}
