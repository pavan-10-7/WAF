"""Detection Adapter for WAF.

Provides a decoupled integration layer between the reverse proxy and the detection engine.
Validates detection outputs against the project contract:
- verdict: 'block' | 'allow'
- attack_type: 'sqli' | 'xss' | 'traversal' | 'none'
- score: float in [0.0, 1.0]
- reason: str

Fails safely: Any detector exception, invalid payload, or contract violation
results in a safe 'block' verdict rather than silently allowing traffic.
"""

import inspect
import logging
from typing import Any, Callable, Dict, Optional

from app.detection_stub import detect as default_detect_stub

logger = logging.getLogger("waf.detection_adapter")

VALID_VERDICTS = {"block", "allow"}
VALID_ATTACK_TYPES = {"sqli", "xss", "traversal", "none"}


class DetectionContractError(Exception):
    """Raised when detection engine returns non-compliant results."""
    pass


class DetectionAdapter:
    """Manages detection function execution, output validation, and safe failure handling."""

    def __init__(self, detector_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None):
        self._detector: Callable[[Dict[str, Any]], Dict[str, Any]] = detector_fn or default_detect_stub

    def set_detector(self, detector_fn: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
        """Allows Member 2's ML detection function to be injected without modifying proxy code."""
        self._detector = detector_fn

    def get_detector(self) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
        return self._detector

    def _validate_response(self, result: Any) -> Dict[str, Any]:
        """Validates that detector response strictly matches the contract."""
        if not isinstance(result, dict):
            raise DetectionContractError(f"Detector must return a dict, got {type(result).__name__}")

        verdict = result.get("verdict")
        if verdict not in VALID_VERDICTS:
            raise DetectionContractError(f"Invalid verdict: {verdict!r}, must be one of {VALID_VERDICTS}")

        attack_type = result.get("attack_type")
        if attack_type not in VALID_ATTACK_TYPES:
            raise DetectionContractError(f"Invalid attack_type: {attack_type!r}, must be one of {VALID_ATTACK_TYPES}")

        score = result.get("score")
        if not isinstance(score, (int, float)) or not (0.0 <= float(score) <= 1.0):
            raise DetectionContractError(f"Score must be a float between 0.0 and 1.0, got {score!r}")

        reason = result.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise DetectionContractError(f"Reason must be a non-empty string, got {reason!r}")

        return {
            "verdict": verdict,
            "attack_type": attack_type,
            "score": float(score),
            "reason": reason.strip(),
        }

    async def detect(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Executes the detector function (synchronous or async) and enforces fail-safe validation."""
        try:
            detector = self._detector
            if inspect.iscoroutinefunction(detector):
                raw_result = await detector(req)
            else:
                raw_result = detector(req)

            validated = self._validate_response(raw_result)
            return validated

        except Exception as exc:
            # Fail-safe security policy: on any detection failure, block the request
            logger.error("Detection failure encountered: %s. Enforcing safe block.", exc)
            return {
                "verdict": "block",
                "attack_type": "none",
                "score": 1.0,
                "reason": f"Safe block: detector execution failed ({exc.__class__.__name__})",
            }


# Global adapter instance for the application
default_adapter = DetectionAdapter()
